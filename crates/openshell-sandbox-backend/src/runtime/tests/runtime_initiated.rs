// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime-initiated transport: admission at the supervisor listener and the
//! client path that shares one listener between discovery and attachment.

use super::*;
use crate::runtime_initiated::RuntimeInitiatedListener;

/// Records when the runtime side of a connection observes EOF or failure.
struct ClosureProbe {
    inner: BoundaryDuplexStream,
    closed: Arc<AtomicBool>,
}

impl tokio::io::AsyncRead for ClosureProbe {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(&result, Poll::Ready(Err(_)))
            || (matches!(&result, Poll::Ready(Ok(()))) && buffer.filled().len() == before)
        {
            self.closed.store(true, Ordering::Release);
        }
        result
    }
}

impl tokio::io::AsyncWrite for ClosureProbe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn runtime_initiated_descriptor(tls: SandboxTlsClientConfig) -> SandboxRuntimeDescriptor {
    let mut descriptor = tls_runtime_descriptor("127.0.0.1:1".parse().unwrap(), tls);
    descriptor.transport = SandboxTransport::RuntimeInitiatedTcp {
        authority: "os-boundary-sandbox-1.ns.svc:5500".to_string(),
        listen_address: "127.0.0.1:5500".parse().unwrap(),
    };
    descriptor
}

/// Production descriptors name a fixed port; tests bind an ephemeral one.
fn bind_ephemeral(tls: &SandboxTlsClientConfig) -> Arc<RuntimeInitiatedListener> {
    RuntimeInitiatedListener::bind_address("127.0.0.1:0".parse().unwrap(), tls).unwrap()
}

/// Dial the listener as `openshell-sandbox` does and complete TLS as the server.
async fn dial_as_runtime(
    address: std::net::SocketAddr,
    server: Arc<rustls::ServerConfig>,
) -> std::io::Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
    let stream = tokio::net::TcpStream::connect(address).await?;
    tokio_rustls::TlsAcceptor::from(server).accept(stream).await
}

/// Dial as the runtime and serve the protocol over the outbound connection.
fn spawn_runtime_connection(
    address: std::net::SocketAddr,
    server: Arc<rustls::ServerConfig>,
    expected_token: &str,
) -> (Arc<AtomicBool>, tokio::task::JoinHandle<()>) {
    let closed = Arc::new(AtomicBool::new(false));
    let probe = closed.clone();
    let expected_token = expected_token.to_string();
    let task = tokio::spawn(async move {
        let stream = dial_as_runtime(address, server).await.unwrap();
        let stream = ClosureProbe {
            inner: Box::new(stream),
            closed: probe,
        };
        serve_test_grpc(Box::new(stream), expected_token).await;
    });
    (closed, task)
}

fn queued(listener: &RuntimeInitiatedListener) -> usize {
    listener.queued_spares()
}

async fn wait_until(condition: impl Fn() -> bool + Send + Sync, failure: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect(failure);
}

async fn assert_closed(stream: &mut (impl tokio::io::AsyncRead + Unpin)) {
    let mut byte = [0; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
}

#[tokio::test]
async fn discovery_and_attach_share_one_listener_and_abort_closes_the_socket() {
    let certificate = test_certificate();
    let descriptor = runtime_initiated_descriptor(certificate.client_tls);
    let listener = bind_ephemeral(&descriptor.tls);
    let address = listener.local_address();
    let transport = BoundaryTransport(TransportSource::RuntimeInitiated(listener));
    let token = "a".repeat(32);

    // Discovery and attachment are separate clients over clones of one
    // transport, as in the supervisor; each takes its own runtime connection.
    let (_, discovery_runtime) =
        spawn_runtime_connection(address, certificate.server_config.clone(), &token);
    let mut discovery = BoundaryClient::new(descriptor.clone(), test_bearer(&token));
    discovery.transport = transport.clone();
    let response =
        tokio::time::timeout(Duration::from_secs(5), discovery.exchange(Request::Confirm))
            .await
            .unwrap()
            .unwrap();
    assert!(matches!(response, Response::Confirmed { .. }));

    let (attach_closed, attach_runtime) =
        spawn_runtime_connection(address, certificate.server_config.clone(), &token);
    let mut client = BoundaryClient::new(descriptor, test_bearer(&token));
    client.transport = transport;
    let response = tokio::time::timeout(Duration::from_secs(5), client.exchange(Request::Confirm))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(response, Response::Confirmed { .. }));

    // Aborting the cached channel closes the runtime's physical socket, and
    // the next request uses a fresh runtime-initiated connection.
    let (replacement_closed, replacement_runtime) =
        spawn_runtime_connection(address, certificate.server_config, &token);
    client
        .grpc_channel
        .lock()
        .await
        .take()
        .unwrap()
        .transport
        .abort();
    wait_until(
        || attach_closed.load(Ordering::Acquire),
        "aborting the channel must close the runtime-initiated socket",
    )
    .await;
    let response = tokio::time::timeout(Duration::from_secs(5), client.exchange(Request::Confirm))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(response, Response::Confirmed { .. }));
    assert!(!replacement_closed.load(Ordering::Acquire));
    for task in [discovery_runtime, attach_runtime, replacement_runtime] {
        task.abort();
    }
}

#[tokio::test]
async fn runtime_initiated_transport_rejects_a_wrong_bearer() {
    let certificate = test_certificate();
    let descriptor = runtime_initiated_descriptor(certificate.client_tls);
    let listener = bind_ephemeral(&descriptor.tls);
    let (_, runtime) = spawn_runtime_connection(
        listener.local_address(),
        certificate.server_config,
        &"a".repeat(32),
    );
    let mut client = BoundaryClient::new(descriptor, test_bearer(&"b".repeat(32)));
    client.transport = BoundaryTransport(TransportSource::RuntimeInitiated(listener));
    let result = tokio::time::timeout(Duration::from_secs(5), client.exchange(Request::Confirm))
        .await
        .unwrap();
    assert!(result.is_err());
    runtime.abort();
}

#[test]
fn runtime_initiated_descriptor_requires_a_fixed_listen_port_and_authority() {
    let certificate = test_certificate();
    let mut descriptor = runtime_initiated_descriptor(certificate.client_tls);
    assert!(validate_runtime_descriptor(&descriptor, &sandbox()).is_ok());
    for (authority, listen_address) in [("", "0.0.0.0:5500"), ("authority:5500", "0.0.0.0:0")] {
        descriptor.transport = SandboxTransport::RuntimeInitiatedTcp {
            authority: authority.to_string(),
            listen_address: listen_address.parse().unwrap(),
        };
        assert!(validate_runtime_descriptor(&descriptor, &sandbox()).is_err());
    }
    // The listener independently refuses an ephemeral production port.
    assert!(matches!(
        RuntimeInitiatedListener::bind(&descriptor),
        Err(BackendError::Descriptor(_))
    ));
}

#[tokio::test]
async fn untrusted_and_silent_peers_cannot_displace_the_genuine_runtime() {
    let genuine = test_certificate();
    let impostor = test_certificate();
    let descriptor = runtime_initiated_descriptor(genuine.client_tls);
    let listener = bind_ephemeral(&descriptor.tls);
    let address = listener.local_address();

    // Silent sockets occupy handshake slots but never reach the queue.
    let mut silent = Vec::new();
    for _ in 0..6 {
        silent.push(tokio::net::TcpStream::connect(address).await.unwrap());
    }
    // A peer presenting another session's identity fails verification. TLS
    // 1.3 servers can finish before the client's alert arrives, so the
    // connection must then be closed without being queued.
    if let Ok(mut rejected) = dial_as_runtime(address, impostor.server_config).await {
        assert_closed(&mut rejected).await;
    }
    assert_eq!(queued(&listener), 0);

    let runtime = tokio::spawn(dial_as_runtime(address, genuine.server_config));
    let accepted = tokio::time::timeout(Duration::from_secs(5), listener.accept(&descriptor)).await;
    assert!(accepted.is_ok_and(|stream| stream.is_ok()));
    assert!(runtime.await.unwrap().is_ok());
    drop(silent);
}

#[tokio::test]
async fn handshake_slots_bound_unauthenticated_sockets() {
    let genuine = test_certificate();
    let descriptor = runtime_initiated_descriptor(genuine.client_tls);
    let listener = bind_ephemeral(&descriptor.tls);
    let address = listener.local_address();
    let mut silent = Vec::new();
    for _ in 0..8 {
        silent.push(tokio::net::TcpStream::connect(address).await.unwrap());
    }
    // Let the listener assign every slot before the excess socket arrives.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut excess = tokio::net::TcpStream::connect(address).await.unwrap();
    assert_closed(&mut excess).await;

    // Freed slots admit the genuine runtime again.
    drop(silent);
    let runtime = tokio::spawn(dial_as_runtime(address, genuine.server_config));
    assert!(
        tokio::time::timeout(Duration::from_secs(10), listener.accept(&descriptor))
            .await
            .is_ok()
    );
    assert!(runtime.await.unwrap().is_ok());
}

#[tokio::test]
async fn spare_queue_is_bounded_and_closes_the_excess_spare() {
    let genuine = test_certificate();
    let descriptor = runtime_initiated_descriptor(genuine.client_tls);
    let listener = bind_ephemeral(&descriptor.tls);
    let mut runtimes = Vec::new();
    for count in 1..=2 {
        runtimes.push(
            dial_as_runtime(listener.local_address(), genuine.server_config.clone())
                .await
                .unwrap(),
        );
        wait_until(
            || queued(&listener) == count,
            "authenticated spare was not queued",
        )
        .await;
    }
    let mut excess = dial_as_runtime(listener.local_address(), genuine.server_config)
        .await
        .unwrap();
    assert_closed(&mut excess).await;
    assert_eq!(queued(&listener), 2);
    drop(runtimes);
}

#[tokio::test]
async fn listener_rejects_an_invalid_pinned_identity_before_binding() {
    let mut tls = test_certificate().client_tls;
    tls.trust_anchor_pem = "not a certificate".to_string();
    assert!(matches!(
        RuntimeInitiatedListener::bind_address("127.0.0.1:0".parse().unwrap(), &tls),
        Err(BackendError::Descriptor(_))
    ));
}

#[tokio::test]
async fn listener_refuses_a_descriptor_for_another_session() {
    let genuine = test_certificate();
    let other = test_certificate();
    let listener = bind_ephemeral(&genuine.client_tls);
    assert!(matches!(
        listener
            .accept(&runtime_initiated_descriptor(other.client_tls))
            .await,
        Err(BackendError::Descriptor(_))
    ));
}

#[tokio::test]
async fn dropping_the_listener_closes_queued_spares() {
    let genuine = test_certificate();
    let listener = bind_ephemeral(&genuine.client_tls);
    let mut runtime = dial_as_runtime(listener.local_address(), genuine.server_config)
        .await
        .unwrap();
    wait_until(
        || queued(&listener) == 1,
        "authenticated spare was not queued",
    )
    .await;
    drop(listener);
    assert_closed(&mut runtime).await;
}
