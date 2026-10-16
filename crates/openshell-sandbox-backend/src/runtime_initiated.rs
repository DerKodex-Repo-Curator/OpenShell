// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor listener for runtime-initiated Sandbox Protocol connections.
//!
//! Only the TCP dial direction is reversed. The supervisor remains the TLS
//! client and gRPC client: it verifies the runtime's generation-pinned server
//! identity on every accepted socket before the socket can carry a request, and
//! every request still carries the Sandbox Protocol bearer token. A peer
//! address is never trusted; it is only the source of a socket to authenticate.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openshell_isolation_interface::contract::{BackendError, BoundaryDuplexStream};

use crate::boundary_protocol::{
    SandboxRuntimeDescriptor, SandboxTlsClientConfig, SandboxTransport,
};

/// Unauthenticated sockets may hold at most this many TLS handshakes.
/// Further sockets are closed immediately rather than queued.
const MAX_PENDING_HANDSHAKES: usize = 8;
/// Upper bound on the time an unauthenticated peer may occupy a slot.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Authenticated connections not yet claimed by a client. The runtime keeps
/// one spare open, so a small bound only absorbs reconnect races.
const MAX_QUEUED_CONNECTIONS: usize = 2;

/// Accepts runtime-initiated connections for exactly one sandbox session.
///
/// Live channels own their streams; this listener only holds unclaimed,
/// already-authenticated spares, so no new connection can evict a live owner.
/// Dropping the listener closes the socket, every pending handshake, and every
/// queued spare.
pub struct RuntimeInitiatedListener {
    tls: SandboxTlsClientConfig,
    local_address: SocketAddr,
    queue: Arc<AdmissionQueue>,
    accept_task: tokio::task::AbortHandle,
}

impl std::fmt::Debug for RuntimeInitiatedListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeInitiatedListener")
            .field("local_address", &self.local_address)
            .field("server_name", &self.tls.server_name)
            .finish_non_exhaustive()
    }
}

impl RuntimeInitiatedListener {
    /// Bind the descriptor's listen address and start authenticating peers.
    ///
    /// Must be called inside a Tokio runtime.
    pub fn bind(descriptor: &SandboxRuntimeDescriptor) -> Result<Arc<Self>, BackendError> {
        let SandboxTransport::RuntimeInitiatedTcp { listen_address, .. } = &descriptor.transport
        else {
            return Err(BackendError::Descriptor(
                "runtime-initiated listener requires a runtime-initiated transport".to_string(),
            ));
        };
        if listen_address.port() == 0 {
            return Err(BackendError::Descriptor(
                "runtime-initiated listen address must have a nonzero port".to_string(),
            ));
        }
        Self::bind_address(*listen_address, &descriptor.tls)
    }

    pub(crate) fn bind_address(
        address: SocketAddr,
        tls: &SandboxTlsClientConfig,
    ) -> Result<Arc<Self>, BackendError> {
        let server_name = rustls::pki_types::ServerName::try_from(tls.server_name.clone())
            .map_err(|error| {
                BackendError::Descriptor(format!(
                    "boundary TLS server name {:?} is invalid: {error}",
                    tls.server_name
                ))
            })?;
        let connector =
            tokio_rustls::TlsConnector::from(Arc::new(crate::runtime::tls_client_config(tls)?));
        let listener = bind_tcp(address).map_err(|error| {
            BackendError::Unavailable(format!(
                "bind runtime-initiated control listener {address}: {error}"
            ))
        })?;
        let local_address = listener.local_addr().map_err(|error| {
            BackendError::Unavailable(format!("read control listener address: {error}"))
        })?;
        let queue = Arc::new(AdmissionQueue::default());
        let accept_task =
            tokio::spawn(accept_loop(listener, connector, server_name, queue.clone()))
                .abort_handle();
        tracing::info!(%local_address, "Runtime-initiated Sandbox Protocol listener ready");
        Ok(Arc::new(Self {
            tls: tls.clone(),
            local_address,
            queue,
            accept_task,
        }))
    }

    /// Address actually bound, including an OS-assigned port.
    #[must_use]
    pub fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    /// Wait for one authenticated runtime connection for `descriptor`.
    ///
    /// The returned stream has completed TLS with the descriptor's pinned
    /// identity. A listener bound for another session is refused.
    pub(crate) async fn accept(
        &self,
        descriptor: &SandboxRuntimeDescriptor,
    ) -> Result<BoundaryDuplexStream, BackendError> {
        if descriptor.tls != self.tls {
            return Err(BackendError::Descriptor(
                "runtime-initiated listener is bound to a different sandbox session".to_string(),
            ));
        }
        Ok(self.queue.pop().await)
    }
}

impl Drop for RuntimeInitiatedListener {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

fn bind_tcp(address: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(64)?;
    tokio::net::TcpListener::from_std(socket.into())
}

#[derive(Default)]
struct AdmissionQueue {
    streams: Mutex<VecDeque<BoundaryDuplexStream>>,
    ready: tokio::sync::Notify,
}

impl AdmissionQueue {
    fn push(&self, stream: BoundaryDuplexStream) {
        let displaced = {
            let mut streams = self
                .streams
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let displaced = (streams.len() >= MAX_QUEUED_CONNECTIONS)
                .then(|| streams.pop_front())
                .flatten();
            streams.push_back(stream);
            displaced
        };
        if displaced.is_some() {
            tracing::debug!("discarding an unclaimed runtime-initiated spare connection");
        }
        self.ready.notify_one();
    }

    async fn pop(&self) -> BoundaryDuplexStream {
        loop {
            let notified = self.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let stream = self
                .streams
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front();
            if let Some(stream) = stream {
                return stream;
            }
            notified.await;
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

async fn accept_loop(
    listener: tokio::net::TcpListener,
    connector: tokio_rustls::TlsConnector,
    server_name: rustls::pki_types::ServerName<'static>,
    queue: Arc<AdmissionQueue>,
) {
    let pending = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_HANDSHAKES));
    // Owned here so aborting this task also cancels every pending handshake.
    let mut handshakes = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        // Descriptor exhaustion and similar errors are transient.
                        tracing::warn!(%error, "runtime-initiated control accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = pending.clone().try_acquire_owned() else {
                    tracing::debug!(%peer, "runtime-initiated handshake limit reached; closing connection");
                    continue;
                };
                openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                crate::runtime::enable_boundary_tcp_keepalive(&stream);
                let connector = connector.clone();
                let server_name = server_name.clone();
                let queue = queue.clone();
                handshakes.spawn(async move {
                    let _permit = permit;
                    match tokio::time::timeout(
                        HANDSHAKE_TIMEOUT,
                        connector.connect(server_name, stream),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => queue.push(Box::new(stream)),
                        Ok(Err(error)) => {
                            tracing::debug!(%peer, %error, "rejected unauthenticated runtime-initiated connection");
                        }
                        Err(_) => {
                            tracing::debug!(%peer, "runtime-initiated TLS handshake timed out");
                        }
                    }
                });
            }
            Some(_) = handshakes.join_next(), if !handshakes.is_empty() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    struct TestIdentity {
        client: SandboxTlsClientConfig,
        server: Arc<rustls::ServerConfig>,
    }

    fn identity() -> TestIdentity {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let material = crate::boundary_protocol::generate_sandbox_tls_material(
            openshell_core::SandboxSessionId::new(),
        )
        .unwrap();
        let certificates = rustls_pemfile::certs(&mut material.certificate_chain_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut material.private_key_pem.as_bytes())
            .unwrap()
            .unwrap();
        let mut server =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(certificates, key)
                .unwrap();
        server.alpn_protocols = vec![b"h2".to_vec()];
        TestIdentity {
            client: SandboxTlsClientConfig {
                server_name: material.server_name,
                trust_anchor_pem: material.trust_anchor_pem,
            },
            server: Arc::new(server),
        }
    }

    fn descriptor(tls: SandboxTlsClientConfig) -> SandboxRuntimeDescriptor {
        SandboxRuntimeDescriptor {
            boundary_id: "sandbox-1".to_string(),
            generation: "generation-1".to_string(),
            session_id: openshell_core::SandboxSessionId::new(),
            workload_identity:
                openshell_isolation_interface::contract::ResolvedWorkloadIdentity::new(
                    1000,
                    1000,
                    Vec::new(),
                    "test".to_string(),
                    "test".to_string(),
                )
                .unwrap(),
            transport: SandboxTransport::RuntimeInitiatedTcp {
                authority: "os-boundary-sandbox-1.ns.svc:5500".to_string(),
                listen_address: "127.0.0.1:0".parse().unwrap(),
            },
            tls,
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            outer_fence: openshell_isolation_interface::contract::OuterFenceGuarantees::from_enforcement_evidence(
                "generation-1",
                [],
                b"test",
            )
            .unwrap(),
        }
    }

    /// Production descriptors require a fixed port; tests bind an ephemeral one.
    fn bind_ephemeral(
        descriptor: &SandboxRuntimeDescriptor,
    ) -> Result<Arc<RuntimeInitiatedListener>, BackendError> {
        RuntimeInitiatedListener::bind_address("127.0.0.1:0".parse().unwrap(), &descriptor.tls)
    }

    #[test]
    fn production_bind_requires_a_fixed_port() {
        let _runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let identity = identity();
        assert!(matches!(
            RuntimeInitiatedListener::bind(&descriptor(identity.client)),
            Err(BackendError::Descriptor(_))
        ));
    }

    /// Dial the listener as the runtime does and serve TLS on the outbound socket.
    async fn dial_as_runtime(
        address: SocketAddr,
        server: Arc<rustls::ServerConfig>,
    ) -> std::io::Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
        let stream = tokio::net::TcpStream::connect(address).await?;
        tokio_rustls::TlsAcceptor::from(server).accept(stream).await
    }

    async fn queued_within(listener: &RuntimeInitiatedListener, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while listener.queue.len() < count {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("authenticated connection was not queued");
    }

    #[tokio::test]
    async fn authenticated_runtime_connection_is_accepted_and_carries_data() {
        let identity = identity();
        let descriptor = descriptor(identity.client);
        let listener = bind_ephemeral(&descriptor).unwrap();
        let runtime = tokio::spawn(dial_as_runtime(listener.local_address(), identity.server));

        let mut supervisor_side =
            tokio::time::timeout(Duration::from_secs(5), listener.accept(&descriptor))
                .await
                .unwrap()
                .unwrap();
        let mut runtime_side = runtime.await.unwrap().unwrap();
        supervisor_side.write_all(b"ping").await.unwrap();
        supervisor_side.flush().await.unwrap();
        let mut received = [0; 4];
        runtime_side.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"ping");
    }

    #[tokio::test]
    async fn untrusted_and_silent_peers_cannot_displace_the_genuine_runtime() {
        let genuine = identity();
        let impostor = identity();
        let descriptor = descriptor(genuine.client);
        let listener = bind_ephemeral(&descriptor).unwrap();
        let address = listener.local_address();

        // Silent sockets occupy handshake slots but never reach the queue.
        let mut silent = Vec::new();
        for _ in 0..(MAX_PENDING_HANDSHAKES - 2) {
            silent.push(tokio::net::TcpStream::connect(address).await.unwrap());
        }
        // A peer presenting another session's identity fails TLS verification.
        let rejected = dial_as_runtime(address, impostor.server).await;
        assert!(
            rejected.is_err() || {
                // TLS 1.3 servers can finish before the client's alert arrives;
                // the connection must then be closed without being queued.
                let mut stream = rejected.unwrap();
                let mut byte = [0; 1];
                stream.read(&mut byte).await.map_or(true, |read| read == 0)
            }
        );
        assert_eq!(listener.queue.len(), 0);

        let runtime = tokio::spawn(dial_as_runtime(address, genuine.server));
        let accepted =
            tokio::time::timeout(Duration::from_secs(5), listener.accept(&descriptor)).await;
        assert!(accepted.is_ok_and(|stream| stream.is_ok()));
        assert!(runtime.await.unwrap().is_ok());
        drop(silent);
    }

    #[tokio::test]
    async fn handshake_slots_bound_unauthenticated_sockets() {
        let genuine = identity();
        let descriptor = descriptor(genuine.client);
        let listener = bind_ephemeral(&descriptor).unwrap();
        let address = listener.local_address();
        let mut silent = Vec::new();
        for _ in 0..MAX_PENDING_HANDSHAKES {
            silent.push(tokio::net::TcpStream::connect(address).await.unwrap());
        }
        // Let the listener assign every slot before the excess socket arrives.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut excess = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut byte = [0; 1];
        let closed = tokio::time::timeout(Duration::from_secs(2), excess.read(&mut byte)).await;
        assert!(
            matches!(closed, Ok(Ok(0) | Err(_))),
            "a socket beyond the handshake limit must be closed"
        );

        // Freed slots admit the genuine runtime again after the timeout.
        drop(silent);
        let runtime = tokio::spawn(dial_as_runtime(address, genuine.server));
        assert!(
            tokio::time::timeout(HANDSHAKE_TIMEOUT * 2, listener.accept(&descriptor))
                .await
                .is_ok()
        );
        assert!(runtime.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn spare_queue_is_bounded_and_never_holds_more_than_the_limit() {
        let genuine = identity();
        let descriptor = descriptor(genuine.client);
        let listener = bind_ephemeral(&descriptor).unwrap();
        let mut runtimes = Vec::new();
        for _ in 0..=MAX_QUEUED_CONNECTIONS {
            runtimes.push(
                dial_as_runtime(listener.local_address(), genuine.server.clone())
                    .await
                    .unwrap(),
            );
        }
        queued_within(&listener, MAX_QUEUED_CONNECTIONS).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(listener.queue.len(), MAX_QUEUED_CONNECTIONS);
        // The oldest spare was displaced and closed.
        let mut byte = [0; 1];
        let oldest = tokio::time::timeout(Duration::from_secs(2), runtimes[0].read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(oldest, Ok(0) | Err(_)));
    }

    #[tokio::test]
    async fn listener_refuses_a_descriptor_for_another_session() {
        let genuine = identity();
        let other = identity();
        let listener = bind_ephemeral(&descriptor(genuine.client)).unwrap();
        assert!(matches!(
            listener.accept(&descriptor(other.client)).await,
            Err(BackendError::Descriptor(_))
        ));
    }

    #[tokio::test]
    async fn dropping_the_listener_closes_queued_connections() {
        let genuine = identity();
        let descriptor = descriptor(genuine.client);
        let listener = bind_ephemeral(&descriptor).unwrap();
        let mut runtime = dial_as_runtime(listener.local_address(), genuine.server)
            .await
            .unwrap();
        queued_within(&listener, 1).await;
        drop(listener);
        let mut byte = [0; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), runtime.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(read, Ok(0) | Err(_)));
    }
}
