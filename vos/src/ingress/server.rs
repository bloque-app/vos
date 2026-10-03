use std::convert::Infallible;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use super::limits::{MAX_BODY_BYTES, MAX_HEADER_BYTES, MAX_HEADERS};
use super::state::Inner;
use super::{HttpIngressContext, decode_access_token};
use crate::node::{IngressAuthenticationError, IngressHandle};

#[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
#[path = "admin.rs"]
mod admin;

fn default_max_connections() -> usize {
    1024
}

const MAX_BLOCKING_REQUESTS: usize = 64;

// Package envelopes can be much larger than ordinary request bodies. Bound
// them across listeners before buffering, and retain admission through decode
// and execution even if the HTTP connection is cancelled.
static LIFECYCLE_UPLOADS: Semaphore = Semaphore::const_new(2);

fn admit_lifecycle_upload(
    maximum_body: usize,
    budget: &Semaphore,
) -> Result<Option<tokio::sync::SemaphorePermit<'_>>, tokio::sync::TryAcquireError> {
    if maximum_body > MAX_BODY_BYTES {
        budget.try_acquire().map(Some)
    } else {
        Ok(None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpTlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpIngressConfig {
    pub name: String,
    pub listen: SocketAddr,
    #[serde(default)]
    pub tls: Option<HttpTlsConfig>,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

#[derive(Debug)]
pub enum HttpIngressError {
    InvalidConfig(&'static str),
    Io(io::Error),
    Tls(String),
}

impl std::fmt::Display for HttpIngressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(message) => f.write_str(message),
            Self::Io(error) => write!(f, "{error}"),
            Self::Tls(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for HttpIngressError {}

impl From<io::Error> for HttpIngressError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub(crate) fn start(
    config: HttpIngressConfig,
    handle: IngressHandle,
) -> Result<thread::JoinHandle<()>, HttpIngressError> {
    if config.name.trim().is_empty() {
        return Err(HttpIngressError::InvalidConfig(
            "HTTP ingress name is empty",
        ));
    }
    if config.max_connections == 0 {
        return Err(HttpIngressError::InvalidConfig(
            "HTTP ingress max_connections must be nonzero",
        ));
    }
    let tls = config.tls.as_ref().map(load_tls).transpose()?;
    let listener = StdTcpListener::bind(config.listen)?;
    listener.set_nonblocking(true)?;
    let name = config.name.clone();
    Ok(thread::Builder::new()
        .name(format!("vos-http-{name}"))
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .thread_name(format!("vos-http-{name}-io"))
                .build()
                .expect("HTTP ingress Tokio runtime");
            runtime.block_on(serve(listener, config, handle, tls));
        })?)
}

async fn serve(
    listener: StdTcpListener,
    config: HttpIngressConfig,
    handle: IngressHandle,
    tls: Option<TlsAcceptor>,
) {
    let listener = match TcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(error) => {
            crate::log::error!("HTTP ingress {} failed: {error}", config.name);
            return;
        }
    };
    let port = listener.local_addr().map_or(0, |address| address.port());
    let inner = Arc::new(Inner::new(port));
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let blocking = Arc::new(Semaphore::new(MAX_BLOCKING_REQUESTS));
    while !handle.is_shutting_down() {
        let accepted = tokio::time::timeout(Duration::from_millis(250), listener.accept()).await;
        let Ok(Ok((stream, _))) = accepted else {
            continue;
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let handle = handle.clone();
        let inner = inner.clone();
        let blocking = blocking.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(tls) = tls {
                match tokio::time::timeout(Duration::from_secs(10), tls.accept(stream)).await {
                    Ok(Ok(stream)) => serve_connection(stream, handle, inner, blocking).await,
                    Ok(Err(error)) => {
                        crate::log::debug!("HTTP TLS handshake rejected: {error}")
                    }
                    Err(_) => crate::log::debug!("HTTP TLS handshake timed out"),
                }
            } else {
                serve_connection(stream, handle, inner, blocking).await;
            }
        });
    }
}

async fn serve_connection<T>(
    stream: T,
    handle: IngressHandle,
    inner: Arc<Inner>,
    blocking: Arc<Semaphore>,
) where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        handle_request(request, handle.clone(), inner.clone(), blocking.clone())
    });
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(true)
        .max_headers(MAX_HEADERS)
        .max_buf_size(MAX_HEADER_BYTES)
        .header_read_timeout(Duration::from_secs(10))
        .timer(TokioTimer::new());
    if let Err(error) = builder
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        crate::log::debug!("HTTP connection closed: {error}");
    }
}

async fn handle_request(
    request: Request<Incoming>,
    handle: IngressHandle,
    inner: Arc<Inner>,
    blocking: Arc<Semaphore>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = request.uri().path().to_string();
    let maximum_body = super::limits::request_body_limit(request.method(), request.uri());
    let upload_permit = match admit_lifecycle_upload(maximum_body, &LIFECYCLE_UPLOADS) {
        Ok(permit) => permit,
        Err(_) => {
            inner.metrics.record_response(503);
            return Ok(simple(
                StatusCode::SERVICE_UNAVAILABLE,
                "lifecycle upload capacity is busy",
            ));
        }
    };
    if request
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > maximum_body as u64)
    {
        inner.metrics.record_response(413);
        return Ok(simple(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large",
        ));
    }
    let (parts, body) = request.into_parts();
    let body = match tokio::time::timeout(
        Duration::from_secs(30),
        Limited::new(body, maximum_body).collect(),
    )
    .await
    {
        Ok(Ok(body)) => body.to_bytes().to_vec(),
        Ok(Err(_)) => {
            inner.metrics.record_response(413);
            return Ok(simple(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ));
        }
        Err(_) => {
            inner.metrics.record_response(408);
            return Ok(simple(
                StatusCode::REQUEST_TIMEOUT,
                "request body timed out",
            ));
        }
    };
    let request = http::Request::from_parts(parts, body);
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    if handle.clean_agent_recovering()
        && !matches!(
            path.as_str(),
            "/__status"
                | "/__agents/authorize"
                | "/__agents/prepare-authorization"
                | "/__agents/admin"
        )
    {
        let response = simple(
            StatusCode::SERVICE_UNAVAILABLE,
            "Space recovering; only exact retained authorization is available",
        );
        inner.metrics.record_response(503);
        return Ok(response);
    }
    let response = if path == "/__status" {
        #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
        if handle.clean_agent_recovering() {
            let response = if request.method() == http::Method::GET {
                simple(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Space recovering; not ready",
                )
            } else {
                simple(StatusCode::METHOD_NOT_ALLOWED, "/__status is GET-only")
            };
            inner.metrics.record_response(response.status().as_u16());
            return Ok(response);
        }
        let mut context = HttpIngressContext::new(handle, None);
        super::routing::dispatch(&request, &inner, &mut context)
    } else {
        let Ok(permit) = blocking.try_acquire_owned() else {
            let response = simple(StatusCode::SERVICE_UNAVAILABLE, "HTTP worker pool is busy");
            inner.metrics.record_response(response.status().as_u16());
            return Ok(response);
        };
        let work_inner = inner.clone();
        match tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _upload_permit = upload_permit;
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            if request.uri().path() == "/__agents/credential" {
                return handle_clean_credential(&request, &handle);
            }
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            if request.uri().path() == "/__agents/inventory" {
                return handle_clean_inventory(&request, &handle);
            }
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            if request.uri().path() == "/__agents/local" {
                return handle_local_create(&request, &handle);
            }
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            if request.uri().path() == "/__agents/local/install" {
                return handle_local_install(&request, &handle);
            }
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            if request.uri().path() == "/__agents/shared" {
                return handle_shared_create(&request, &handle);
            }
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            if request.uri().path() == "/__agents/shared/install" {
                return handle_shared_install(&request, &handle);
            }
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            if request.uri().path() == "/__agents/authorize" {
                return handle_operation_authorization(&request, &handle);
            }
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            if request.uri().path() == "/__agents/prepare-authorization" {
                return handle_operation_preparation(&request, &handle);
            }
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            if request.uri().path() == "/__agents/admin/prepare" {
                return admin::prepare(&request, &handle);
            }
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            if request.uri().path() == "/__agents/admin" {
                return admin::submit(&request, &handle);
            }
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            if matches!(
                request.uri().path(),
                "/__agents/invoke" | "/__agents/resume" | "/__agents/acknowledge"
            ) {
                return handle_clean_invocation(&request, &handle);
            }
            #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
            if request.uri().path() == "/__agents/prepare" {
                return handle_clean_preparation(&request, &handle);
            }
            let access = match authenticate(&request, &handle) {
                Ok(access) => access,
                Err((status, message)) => return simple_bytes(status, message),
            };
            let mut context = HttpIngressContext::new(handle, Some(access));
            super::routing::dispatch(&request, &work_inner, &mut context)
        })
        .await
        {
            Ok(response) => response,
            Err(_) => super::types::text(500, "HTTP worker failed"),
        }
    };
    inner.metrics.record_response(response.status().as_u16());
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(parts, Full::new(Bytes::from(body))))
}

#[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
fn handle_clean_credential(
    request: &super::types::Request,
    handle: &IngressHandle,
) -> super::types::Response {
    use super::types::{text, with_content_type};
    use crate::agent::sdk::authority::AuthorityProjectionQuery;
    use crate::agent::sdk::wire::CanonicalWire as _;
    if request.method() != http::Method::POST {
        return text(405, "credential query is POST-only");
    }
    if request.uri().query().is_some() {
        return text(400, "credential query does not accept query parameters");
    }
    if request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
    {
        return text(415, "credential query requires application/octet-stream");
    }
    let query = match AuthorityProjectionQuery::decode(request.body()) {
        Ok(query) => query,
        Err(_) => return text(400, "invalid clean credential query"),
    };
    match handle.query_clean_credential(query) {
        Ok(projection) => match projection.encode() {
            Ok(bytes) => with_content_type(200, "application/octet-stream", bytes),
            Err(_) => text(503, "invalid Authority projection"),
        },
        Err(IngressAuthenticationError::Invalid) => text(403, "invalid API credential query"),
        Err(IngressAuthenticationError::AuthorityUnavailable) => text(
            503,
            "clean Authority unavailable; retry the identical signed query",
        ),
    }
}

#[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
fn handle_clean_inventory(
    request: &super::types::Request,
    handle: &IngressHandle,
) -> super::types::Response {
    use super::types::{text, with_content_type};
    use crate::agent::sdk::authority::AuthorityProjectionQuery;
    use crate::agent::sdk::wire::CanonicalWire as _;
    if request.body().len() > crate::agent::sdk::wire::MAX_AUTHORITY_PROJECTION_QUERY_WIRE_BYTES {
        return text(413, "inventory query too large");
    }
    if request.method() != http::Method::POST {
        return text(405, "inventory query is POST-only");
    }
    if request.uri().query().is_some() {
        return text(400, "inventory query does not accept query parameters");
    }
    if request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
    {
        return text(415, "inventory query requires application/octet-stream");
    }
    let query = match AuthorityProjectionQuery::decode(request.body()) {
        Ok(query) => query,
        Err(_) => return text(400, "invalid clean inventory query"),
    };
    match handle.query_clean_agent_inventory(query) {
        Ok(bytes) => with_content_type(200, "application/octet-stream", bytes),
        Err(IngressAuthenticationError::Invalid) => text(403, "invalid API inventory query"),
        Err(IngressAuthenticationError::AuthorityUnavailable) => text(
            503,
            "clean Authority unavailable; retry the identical signed query",
        ),
    }
}

/// Signed-body authentication: image Local LCQ1 verifies ACC3 locally;
/// the live Authority independently authorizes the exact request before issue.
#[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
fn handle_local_create(
    request: &super::types::Request,
    handle: &IngressHandle,
) -> super::types::Response {
    use super::types::{text, with_content_type};
    if request.body().len() > crate::agent::local_lifecycle::LocalCreateSubmission::MAX_BYTES {
        return text(413, "request body too large");
    }
    use crate::agent::local_lifecycle::{LocalCreateSubmission, LocalLifecycleIngressError};
    use crate::agent::sdk::wire::CanonicalWire as _;
    if request.method() != http::Method::POST {
        return text(405, "Local Create is POST-only");
    }
    if request.uri().query().is_some() {
        return text(400, "Local Create does not accept query parameters");
    }
    if request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
    {
        return text(415, "Local Create requires application/octet-stream");
    }
    let pending = if request.body().starts_with(b"LCQ2") {
        // The experimental codec remains for storage qualification, not public
        // Local admission. Refuse before decoding, queueing or durable work in
        // every feature combination; v1 Local roots remain image-based.
        return text(400, "external Local Create is not supported in v1");
    } else {
        let submission = match LocalCreateSubmission::decode(request.body()) {
            Ok(value) => value,
            Err(_) => return text(400, "invalid signed Local Create submission"),
        };
        let (descriptor, call, runtime) = submission.into_parts();
        // HTTP cannot attest a transport/node binding. The signed credential
        // call still needs independent authorization by the Authority actor.
        if call.authenticated_node.is_some() {
            return text(
                403,
                "HTTP Local Create does not accept transport-node claims",
            );
        }
        handle.create_clean_local_agent(descriptor, call, runtime)
    };
    let reply = match pending {
        Ok(reply) => reply,
        Err(LocalLifecycleIngressError::Invalid) => return text(400, "invalid Local Create"),
        Err(LocalLifecycleIngressError::Busy) => return text(503, "Local lifecycle queue is full"),
        Err(LocalLifecycleIngressError::Unavailable) => {
            return text(503, "Local lifecycle unavailable");
        }
    };
    match reply.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(crate::agent::local_lifecycle::LocalCreateDisposition::Created(
            _,
            acknowledgement,
        ))) => match acknowledgement.encode() {
            Ok(bytes) => with_content_type(201, "application/octet-stream", bytes),
            Err(_) => text(500, "invalid lifecycle acknowledgement"),
        },
        Ok(Ok(crate::agent::local_lifecycle::LocalCreateDisposition::Denied(denial))) => {
            with_content_type(
                403,
                "application/octet-stream",
                denial.exact_bytes().to_vec(),
            )
        }
        Ok(Err(crate::agent::production_owner::AgentProductionOwnerError::Lifecycle(
            crate::agent::shared_host::SharedAgentHostError::ScopeMismatch,
        ))) => text(403, "Local Create scope or authorization rejected"),
        Ok(Err(error)) => {
            crate::log::warn!("Local Create did not complete: {error:?}");
            local_lifecycle_failure(
                error,
                "Local Create incomplete; retry the identical signed submission",
            )
        }
        Err(_) => text(
            504,
            "Local Create outcome unknown; retry the identical signed submission",
        ),
    }
}

#[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
fn handle_operation_preparation(
    request: &super::types::Request,
    handle: &IngressHandle,
) -> super::types::Response {
    use super::types::{text, with_content_type};
    use crate::agent::local_lifecycle::LocalLifecycleIngressError;
    use crate::agent::sdk::authority_operation::AuthorityOperationCall;
    use crate::agent::sdk::wire::CanonicalWire as _;
    if request.body().len() > MAX_BODY_BYTES.min(AuthorityOperationCall::MAX_ENCODED_BYTES) {
        return text(413, "operation preparation body too large");
    }
    if request.method() != http::Method::POST {
        return text(405, "operation preparation is POST-only");
    }
    if request.uri().query().is_some() {
        return text(
            400,
            "operation preparation does not accept query parameters",
        );
    }
    if request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some("application/octet-stream")
    {
        return text(
            415,
            "operation preparation requires application/octet-stream AOC5",
        );
    }
    let call = match AuthorityOperationCall::decode(request.body()) {
        Ok(call) => call,
        Err(_) => return text(400, "invalid operation call"),
    };
    if call.authenticated_node().is_some() {
        return text(
            403,
            "HTTP operation preparation does not accept transport-node claims",
        );
    }
    let reply = match handle.prepare_clean_agent_operation(call.clone()) {
        Ok(reply) => reply,
        Err(LocalLifecycleIngressError::Invalid) => {
            return text(400, "invalid signed operation call");
        }
        Err(LocalLifecycleIngressError::Busy) => return text(503, "Local lifecycle queue is full"),
        Err(LocalLifecycleIngressError::Unavailable) => {
            return text(503, "operation preparation unavailable");
        }
    };
    match reply.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(submission)) if submission.call() == &call => match submission.encode() {
            Ok(bytes) => with_content_type(200, "application/octet-stream", bytes),
            Err(_) => text(500, "invalid prepared operation submission"),
        },
        Ok(Ok(_)) => text(500, "invalid operation preparation binding"),
        Ok(Err(error)) => {
            tracing::warn!(?error, "native operation preparation incomplete");
            text(
                503,
                "operation preparation incomplete; retry identical AOC5",
            )
        }
        Err(_) => text(
            504,
            "operation preparation outcome unknown; retry identical AOC5",
        ),
    }
}

#[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
fn handle_operation_authorization(
    request: &super::types::Request,
    handle: &IngressHandle,
) -> super::types::Response {
    use super::types::{text, with_content_type};
    use crate::agent::local_lifecycle::{AuthorityOperationSubmission, LocalLifecycleIngressError};
    use crate::agent::sdk::wire::CanonicalWire as _;
    if request.body().len() > MAX_BODY_BYTES.min(AuthorityOperationSubmission::MAX_ENCODED_BYTES) {
        return text(413, "operation request body too large");
    }
    if request.method() != http::Method::POST {
        return text(405, "operation authorization is POST-only");
    }
    if request.uri().query().is_some() {
        return text(
            400,
            "operation authorization does not accept query parameters",
        );
    }
    if request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some("application/octet-stream")
    {
        return text(
            415,
            "operation authorization requires application/octet-stream AOQ1",
        );
    }
    let submission = match AuthorityOperationSubmission::decode(request.body()) {
        Ok(value) => value,
        Err(_) => return text(400, "invalid signed operation submission"),
    };
    if submission.call().authenticated_node().is_some() {
        return text(
            403,
            "HTTP operation authorization does not accept transport-node claims",
        );
    }
    let reply = match handle.submit_clean_agent_operation(submission.clone()) {
        Ok(reply) => reply,
        Err(LocalLifecycleIngressError::Invalid) => {
            return text(400, "invalid operation submission");
        }
        Err(LocalLifecycleIngressError::Busy) => return text(503, "Local lifecycle queue is full"),
        Err(LocalLifecycleIngressError::Unavailable) => {
            return text(503, "operation authorization unavailable");
        }
    };
    match reply.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(decision)) => match submission.encode_response(&decision) {
            // Both verified policy outcomes are completed decisions; callers
            // distinguish issuance/denial from the authenticated AOR1 payload.
            Ok(bytes) => with_content_type(200, "application/octet-stream", bytes),
            Err(_) => text(500, "invalid operation response binding"),
        },
        Ok(Err(error)) => {
            tracing::warn!(?error, "native operation authorization incomplete");
            text(
                503,
                "operation authorization incomplete; retry identical AOQ1",
            )
        }
        Err(_) => text(
            504,
            "operation authorization outcome unknown; retry identical AOQ1",
        ),
    }
}

#[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
fn handle_local_install(
    request: &super::types::Request,
    handle: &IngressHandle,
) -> super::types::Response {
    use super::types::{text, with_content_type};
    use crate::agent::local_lifecycle::{LocalInstallSubmission, LocalLifecycleIngressError};
    use crate::agent::sdk::wire::CanonicalWire as _;
    if request.body().len() > LocalInstallSubmission::MAX_BYTES {
        return text(413, "request body too large");
    }
    if request.method() != http::Method::POST {
        return text(405, "Local Install is POST-only");
    }
    if request.uri().query().is_some() {
        return text(400, "Local Install does not accept query parameters");
    }
    if request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
    {
        return text(415, "Local Install requires application/octet-stream LIQ1");
    }
    let submission = match LocalInstallSubmission::decode(request.body()) {
        Ok(value) => value,
        Err(_) => return text(400, "invalid signed Local Install submission"),
    };
    if submission.has_transport_node_claim() {
        return text(
            403,
            "HTTP Local Install does not accept transport-node claims",
        );
    }
    let reply = match handle.install_clean_local_actor(submission) {
        Ok(reply) => reply,
        Err(LocalLifecycleIngressError::Invalid) => return text(400, "invalid Local Install"),
        Err(LocalLifecycleIngressError::Busy) => return text(503, "Local lifecycle queue is full"),
        Err(LocalLifecycleIngressError::Unavailable) => {
            return text(503, "Local lifecycle unavailable");
        }
    };
    match reply.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(acknowledgement)) => match acknowledgement.encode() {
            Ok(bytes) => with_content_type(201, "application/octet-stream", bytes),
            Err(_) => text(500, "invalid lifecycle acknowledgement"),
        },
        Ok(Err(error)) => {
            crate::log::warn!("Local Install did not complete: {error:?}");
            local_lifecycle_failure(
                error,
                "Local Install incomplete; retry the identical signed submission",
            )
        }
        Err(_) => text(
            504,
            "Local Install outcome unknown; retry the identical signed submission",
        ),
    }
}

#[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
fn shared_lifecycle_request_error(
    request: &super::types::Request,
    maximum: usize,
    label: &'static str,
) -> Option<super::types::Response> {
    use super::types::text;
    if request.body().len() > maximum {
        return Some(text(413, "request body too large"));
    }
    if request.method() != http::Method::POST {
        return Some(text(405, label));
    }
    if request.uri().query().is_some() {
        return Some(text(
            400,
            "Shared lifecycle does not accept query parameters",
        ));
    }
    if request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
    {
        return Some(text(
            415,
            "Shared lifecycle requires application/octet-stream",
        ));
    }
    None
}

/// Exact signed ordinary Shared Create (SCQ1). The daemon endorses only with
/// its configured root credential; publication, finality and route exposure
/// remain owner-verified. HTTP cannot attest a transport/node binding.
#[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
fn handle_shared_create(
    request: &super::types::Request,
    handle: &IngressHandle,
) -> super::types::Response {
    use super::types::{text, with_content_type};
    use crate::agent::local_lifecycle::{LocalLifecycleIngressError, SharedCreateSubmission};
    use crate::agent::sdk::wire::CanonicalWire as _;
    if let Some(response) = shared_lifecycle_request_error(
        request,
        SharedCreateSubmission::MAX_BYTES,
        "Shared Create is POST-only",
    ) {
        return response;
    }
    let submission = match SharedCreateSubmission::decode(request.body()) {
        Ok(value) => value,
        Err(_) => return text(400, "invalid signed Shared Create submission"),
    };
    if submission.call().authenticated_node.is_some() {
        return text(
            403,
            "HTTP Shared Create does not accept transport-node claims",
        );
    }
    let reply = match handle.create_clean_shared_agent(submission) {
        Ok(reply) => reply,
        Err(LocalLifecycleIngressError::Invalid) => return text(400, "invalid Shared Create"),
        Err(LocalLifecycleIngressError::Busy) => return text(503, "Local lifecycle queue is full"),
        Err(LocalLifecycleIngressError::Unavailable) => {
            return text(503, "Shared lifecycle unavailable");
        }
    };
    match reply.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(acknowledgement)) => match acknowledgement.encode() {
            Ok(bytes) => with_content_type(201, "application/octet-stream", bytes),
            Err(_) => text(500, "invalid lifecycle acknowledgement"),
        },
        Ok(Err(crate::agent::production_owner::AgentProductionOwnerError::Lifecycle(
            crate::agent::shared_host::SharedAgentHostError::ScopeMismatch,
        ))) => text(403, "Shared Create scope or authorization rejected"),
        Ok(Err(error)) => {
            crate::log::warn!("Shared Create did not complete: {error:?}");
            local_lifecycle_failure(
                error,
                "Shared Create incomplete; retry the identical signed submission",
            )
        }
        Err(_) => text(
            504,
            "Shared Create outcome unknown; retry the identical signed submission",
        ),
    }
}

/// Exact signed ordinary Shared Install (SIQ1). A 403 carries the signed
/// denial certificate for this exact request; other refusals carry text.
#[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
fn handle_shared_install(
    request: &super::types::Request,
    handle: &IngressHandle,
) -> super::types::Response {
    use super::types::{text, with_content_type};
    use crate::agent::local_lifecycle::{
        LocalLifecycleIngressError, SharedInstallDisposition, SharedInstallSubmission,
    };
    use crate::agent::sdk::wire::CanonicalWire as _;
    if let Some(response) = shared_lifecycle_request_error(
        request,
        SharedInstallSubmission::MAX_BYTES,
        "Shared Install is POST-only",
    ) {
        return response;
    }
    let submission = match SharedInstallSubmission::decode(request.body()) {
        Ok(value) => value,
        Err(_) => return text(400, "invalid signed Shared Install submission"),
    };
    if submission.call().authenticated_node.is_some() {
        return text(
            403,
            "HTTP Shared Install does not accept transport-node claims",
        );
    }
    let reply = match handle.install_clean_shared_actor(submission) {
        Ok(reply) => reply,
        Err(LocalLifecycleIngressError::Invalid) => return text(400, "invalid Shared Install"),
        Err(LocalLifecycleIngressError::Busy) => return text(503, "Local lifecycle queue is full"),
        Err(LocalLifecycleIngressError::Unavailable) => {
            return text(503, "Shared lifecycle unavailable");
        }
    };
    match reply.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(SharedInstallDisposition::Installed(acknowledgement))) => {
            match acknowledgement.encode() {
                Ok(bytes) => with_content_type(201, "application/octet-stream", bytes),
                Err(_) => text(500, "invalid lifecycle acknowledgement"),
            }
        }
        Ok(Ok(SharedInstallDisposition::Denied(denial))) => with_content_type(
            403,
            "application/octet-stream",
            denial.exact_bytes().to_vec(),
        ),
        Ok(Err(crate::agent::production_owner::AgentProductionOwnerError::Lifecycle(
            crate::agent::shared_host::SharedAgentHostError::ScopeMismatch,
        ))) => text(422, "Shared Install scope rejected or application refused"),
        Ok(Err(error)) => {
            crate::log::warn!("Shared Install did not complete: {error:?}");
            local_lifecycle_failure(
                error,
                "Shared Install incomplete; retry the identical signed submission",
            )
        }
        Err(_) => text(
            504,
            "Shared Install outcome unknown; retry the identical signed submission",
        ),
    }
}

#[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
fn local_lifecycle_failure(
    error: crate::agent::production_owner::AgentProductionOwnerError,
    unavailable: &'static str,
) -> super::types::Response {
    use crate::agent::{
        production_owner::AgentProductionOwnerError, shared_host::SharedAgentHostError,
    };
    if matches!(
        error,
        AgentProductionOwnerError::Lifecycle(SharedAgentHostError::Conflict)
    ) {
        super::types::text(
            409,
            "Local lifecycle conflicts with retained state; inspect retained operation evidence before retrying",
        )
    } else {
        super::types::text(503, unavailable)
    }
}

/// Forward canonical clean lifecycle envelopes around actor messages. Receipt
/// authorization remains the selected runtime's responsibility. An unsigned
/// PublicPreflight is not proof of any caller identity, even for Public methods.
#[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
fn handle_clean_invocation(
    request: &super::types::Request,
    handle: &IngressHandle,
) -> super::types::Response {
    use super::types::{text, with_content_type};
    use crate::agent::sdk::wire::CanonicalWire as _;
    use crate::agent::sdk::{
        InvocationAuthorization, InvocationOrigin, InvocationRoleClaims, RuntimeExecutionContext,
    };
    use crate::agent::supervisor::AgentRouteKey;
    use crate::agent::supervisor_adapters::{
        AgentAcknowledgementRequest, AgentInvocationRequest, AgentResumeRequest,
        dispatch_encoded_acknowledgement, dispatch_encoded_invocation, dispatch_encoded_resume,
    };

    if request.body().len() > MAX_BODY_BYTES {
        return text(413, "request body too large");
    }
    if request.method() != http::Method::POST {
        return text(405, "clean invocation is POST-only");
    }
    if request.uri().query().is_some() {
        return text(400, "clean invocation does not accept query parameters");
    }
    if request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
    {
        return text(
            415,
            "clean invocation requires application/octet-stream with the endpoint's canonical frame",
        );
    }
    let decoded = match request.uri().path() {
        "/__agents/resume" => AgentResumeRequest::decode(request.body()).map(|value| {
            (
                value.execution(),
                value.work().clone(),
                value.authorization().clone(),
            )
        }),
        "/__agents/acknowledge" => {
            AgentAcknowledgementRequest::decode(request.body()).map(|value| {
                (
                    value.execution(),
                    value.work().clone(),
                    value.authorization().clone(),
                )
            })
        }
        _ => AgentInvocationRequest::decode(request.body()).map(|value| {
            (
                value.execution(),
                value.work().clone(),
                value.authorization().clone(),
            )
        }),
    };
    let (execution, work, authorization) = match decoded {
        Ok(value) => value,
        Err(_) => return text(400, "invalid canonical clean invocation"),
    };
    // Generic supervisor responses do not carry the sealed proof-verification
    // capability required for attested delivery. Reject before any execution.
    if execution != RuntimeExecutionContext::Direct {
        return text(501, "attested HTTP invocation is not yet available");
    }
    if work.origin.transport_node.is_some() {
        return text(403, "HTTP invocation does not accept transport-node claims");
    }
    if matches!(authorization, InvocationAuthorization::PublicPreflight(_))
        && (work.origin != InvocationOrigin::anonymous()
            || work.roles != InvocationRoleClaims::none())
    {
        return text(
            403,
            "unsigned public invocation cannot assert caller identity or roles",
        );
    }
    let Some(supervisor) = handle.clean_agent_supervisor() else {
        return text(503, "clean agent supervisor unavailable");
    };
    let key = match AgentRouteKey::new(work.space, work.agent, work.actor) {
        Ok(key) => key,
        Err(_) => return text(400, "invalid clean invocation route"),
    };
    let snapshot = match supervisor.snapshot(key) {
        Ok(snapshot) => snapshot,
        Err(_) => return text(503, "clean invocation route unavailable"),
    };
    // The exact bytes, including authorization and recovery intent, survive
    // retries. Dispatch checks the live identity and exact response commitment.
    // Never interpret a transport error as proof that execution did not occur.
    let response = match request.uri().path() {
        "/__agents/resume" => dispatch_encoded_resume(&supervisor, snapshot, request.body())
            .map(|response| response.encode()),
        "/__agents/acknowledge" => {
            dispatch_encoded_acknowledgement(&supervisor, snapshot, request.body())
                .map(|response| response.encode())
        }
        _ => dispatch_encoded_invocation(&supervisor, snapshot, request.body())
            .map(|response| response.encode()),
    };
    match response {
        Ok(response) => match response {
            Ok(bytes) => with_content_type(200, "application/octet-stream", bytes),
            Err(_) => text(
                503,
                "clean invocation response unavailable; retain exact request",
            ),
        },
        Err(_) => text(
            503,
            "clean invocation incomplete; retain and retry the exact request",
        ),
    }
}

#[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
fn handle_clean_preparation(
    request: &super::types::Request,
    handle: &IngressHandle,
) -> super::types::Response {
    use super::types::{text, with_content_type};
    use crate::agent::sdk::wire::CanonicalWire as _;
    use crate::agent::supervisor_adapters::{
        AgentTargetedPreparationRequest, prepare_targeted_invocation,
    };
    if request.body().len() > MAX_BODY_BYTES {
        return text(413, "request body too large");
    }
    if request.method() != http::Method::POST {
        return text(405, "clean preparation is POST-only");
    }
    if request.uri().query().is_some() {
        return text(400, "clean preparation does not accept query parameters");
    }
    if request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
    {
        return text(
            415,
            "clean preparation requires application/octet-stream ATQ1",
        );
    }
    let preparation = match AgentTargetedPreparationRequest::decode(request.body()) {
        Ok(value) => value,
        Err(_) => return text(400, "invalid canonical clean preparation"),
    };
    // Clean inventory is visible to active enrolled credentials (Private
    // preparation remains forbidden). Do not invent legacy capability grants
    // from clean built-in roles. Actor execution still needs its own policy.
    let Some(credential) = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(decode_access_token)
    else {
        return text(401, "invalid access token");
    };
    let mut nonce = [0; 32];
    if getrandom::getrandom(&mut nonce).is_err() || nonce == [0; 32] {
        return text(503, "credential query nonce unavailable");
    }
    let access = match handle.authenticate_clean_api(&credential, crate::agent::sdk::Hash(nonce)) {
        Ok(access) => access,
        Err(IngressAuthenticationError::Invalid) => return text(401, "invalid access token"),
        Err(IngressAuthenticationError::AuthorityUnavailable) => {
            return text(503, "clean authority unavailable");
        }
    };
    if access.status != crate::agent::sdk::authority::AuthorityCredentialStatus::Active
        || access.kind != crate::agent::sdk::authority::AuthorityCredentialKind::Api
    {
        return text(403, "active API credential required for clean preparation");
    }
    let Some(supervisor) = handle.clean_agent_supervisor() else {
        return text(503, "clean agent supervisor unavailable");
    };
    match prepare_targeted_invocation(&supervisor, &preparation) {
        Ok(response) => match response.encode() {
            Ok(bytes) => with_content_type(200, "application/octet-stream", bytes),
            Err(_) => text(503, "clean preparation response unavailable"),
        },
        Err(error) => {
            tracing::warn!(?error, "clean invocation preparation failed");
            text(503, "clean preparation unavailable")
        }
    }
}

fn authenticate<B>(
    request: &Request<B>,
    handle: &IngressHandle,
) -> Result<crate::IngressAccessStatus, (StatusCode, &'static str)> {
    let credential = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(decode_access_token)
        .ok_or((StatusCode::UNAUTHORIZED, "invalid access token"))?;
    let credential_id = credential.credential_id().0;
    let access = match handle.authenticate_credential(credential_id) {
        Ok(access) => access,
        Err(IngressAuthenticationError::Invalid) => {
            return Err((StatusCode::UNAUTHORIZED, "invalid access token"));
        }
        Err(IngressAuthenticationError::AuthorityUnavailable) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "space authority unavailable",
            ));
        }
    };
    if access.expires_at <= super::state::now_unix() {
        return Err((StatusCode::UNAUTHORIZED, "access token expired"));
    }
    Ok(access)
}

fn simple_bytes(status: StatusCode, message: &'static str) -> super::types::Response {
    super::types::text(status.as_u16(), message)
}

fn simple(status: StatusCode, message: &'static str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(message.as_bytes())));
    *response.status_mut() = status;
    response
}

fn load_tls(config: &HttpTlsConfig) -> Result<TlsAcceptor, HttpIngressError> {
    let mut cert = std::io::BufReader::new(std::fs::File::open(&config.cert)?);
    let certificates = rustls_pemfile::certs(&mut cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| HttpIngressError::Tls(error.to_string()))?;
    if certificates.is_empty() {
        return Err(HttpIngressError::Tls(
            "TLS certificate chain is empty".into(),
        ));
    }
    let mut key = std::io::BufReader::new(std::fs::File::open(&config.key)?);
    let key = rustls_pemfile::private_key(&mut key)
        .map_err(|error| HttpIngressError::Tls(error.to_string()))?
        .ok_or_else(|| HttpIngressError::Tls("TLS private key is missing".into()))?;
    let server = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|error| HttpIngressError::Tls(error.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(server)))
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    #[test]
    fn lifecycle_conflict_is_not_temporary_unavailability() {
        use crate::agent::{
            production_owner::AgentProductionOwnerError, shared_host::SharedAgentHostError,
        };
        let conflict = super::local_lifecycle_failure(
            AgentProductionOwnerError::Lifecycle(SharedAgentHostError::Conflict),
            "unavailable",
        );
        assert_eq!(conflict.status().as_u16(), 409);
        assert!(
            std::str::from_utf8(conflict.body())
                .unwrap()
                .contains("inspect retained")
        );
        for error in [
            AgentProductionOwnerError::Lifecycle(SharedAgentHostError::Unavailable),
            AgentProductionOwnerError::InvalidProjection,
        ] {
            assert_eq!(
                super::local_lifecycle_failure(error, "unavailable")
                    .status()
                    .as_u16(),
                503
            );
        }
    }
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    #[test]
    fn local_lifecycle_rejects_noncanonical_http_and_unsigned_frames() {
        let node = crate::node::VosNode::new();
        let handle = node.ingress_handle();
        for (method, path, content_type, body, expected) in [
            (
                "GET",
                "/__agents/local",
                "application/octet-stream",
                Vec::new(),
                405,
            ),
            (
                "POST",
                "/__agents/local?alias=1",
                "application/octet-stream",
                Vec::new(),
                400,
            ),
            (
                "POST",
                "/__agents/local",
                "application/json",
                Vec::new(),
                415,
            ),
            (
                "POST",
                "/__agents/local",
                "application/octet-stream",
                b"LCQ1".to_vec(),
                400,
            ),
            (
                "POST",
                "/__agents/local",
                "application/octet-stream",
                b"LCQ2".to_vec(),
                400,
            ),
            (
                "POST",
                "/__agents/local",
                "application/octet-stream",
                vec![0; crate::agent::local_lifecycle::LocalCreateSubmission::MAX_BYTES + 1],
                413,
            ),
        ] {
            let request = http::Request::builder()
                .method(method)
                .uri(path)
                .header(http::header::CONTENT_TYPE, content_type)
                .body(body)
                .unwrap();
            let response = handle_local_create(&request, &handle);
            assert_eq!(response.status().as_u16(), expected);
            if request.body().starts_with(b"LCQ2") {
                assert_eq!(
                    response.body(),
                    b"external Local Create is not supported in v1"
                );
            }
            assert_eq!(
                handle_clean_invocation(&request, &handle).status().as_u16(),
                expected
            );
            assert_eq!(
                handle_operation_authorization(&request, &handle)
                    .status()
                    .as_u16(),
                expected
            );
            assert_eq!(
                handle_operation_preparation(&request, &handle)
                    .status()
                    .as_u16(),
                expected
            );
            assert_eq!(
                admin::prepare(&request, &handle).status().as_u16(),
                expected
            );
            assert_eq!(admin::submit(&request, &handle).status().as_u16(), expected);
            assert_eq!(
                handle_clean_preparation(&request, &handle)
                    .status()
                    .as_u16(),
                expected
            );
            let (mut parts, mut body) = request.into_parts();
            parts.uri = path
                .replace("/__agents/local", "/__agents/local/install")
                .parse()
                .unwrap();
            if body == b"LCQ1" {
                body = b"LIQ1".to_vec();
            }
            let request = http::Request::from_parts(parts, body);
            assert_eq!(
                handle_local_install(&request, &handle).status().as_u16(),
                expected
            );
        }
    }
    use std::io::{Read, Write};

    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    #[test]
    fn lifecycle_package_bodies_above_default_limit_still_require_valid_signatures() {
        let node = crate::node::VosNode::new();
        let handle = node.ingress_handle();
        let request = http::Request::builder()
            .method("POST")
            .uri("/__agents/local")
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .body(vec![0; MAX_BODY_BYTES + 1])
            .unwrap();
        assert_eq!(
            handle_local_create(&request, &handle).status().as_u16(),
            400
        );
        assert_eq!(
            handle_local_install(&request, &handle).status().as_u16(),
            400
        );
        assert_eq!(
            handle_clean_invocation(&request, &handle).status().as_u16(),
            413
        );
    }

    use super::*;
    use crate::node::VosNode;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[test]
    fn lifecycle_upload_admission_is_bounded_and_released_without_blocking_small_bodies() {
        let budget = Semaphore::new(2);
        let first = admit_lifecycle_upload(MAX_BODY_BYTES + 1, &budget).unwrap();
        let second = admit_lifecycle_upload(MAX_BODY_BYTES + 1, &budget).unwrap();
        assert!(admit_lifecycle_upload(MAX_BODY_BYTES + 1, &budget).is_err());
        assert!(
            admit_lifecycle_upload(MAX_BODY_BYTES, &budget)
                .unwrap()
                .is_none()
        );
        drop(first);
        let replacement = admit_lifecycle_upload(MAX_BODY_BYTES + 1, &budget).unwrap();
        drop((second, replacement));
        assert_eq!(budget.available_permits(), 2);
    }

    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_buffers_package_envelopes_but_keeps_other_routes_at_default_limit() {
        let node = VosNode::new();
        for (path, expected) in [
            ("/__agents/local", "HTTP/1.1 400"),
            ("/__agents/local/install", "HTTP/1.1 400"),
            ("/__agents/local/", "HTTP/1.1 413"),
            ("/__agents/invoke", "HTTP/1.1 413"),
        ] {
            let (mut client, server) = tokio::io::duplex(2 * MAX_BODY_BYTES);
            let serving = tokio::spawn(serve_connection(
                server,
                node.ingress_handle(),
                Arc::new(Inner::new(0)),
                Arc::new(Semaphore::new(2)),
            ));
            let body = vec![0; MAX_BODY_BYTES + 1];
            let headers = format!(
                "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            client.write_all(headers.as_bytes()).await.unwrap();
            if expected.ends_with("400") {
                client.write_all(&body).await.unwrap();
            }
            let mut response = String::new();
            tokio::time::timeout(Duration::from_secs(5), client.read_to_string(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert!(response.starts_with(expected), "{path}: {response}");
            serving.await.unwrap();
        }
    }

    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    #[test]
    fn clean_invocation_rejects_unsigned_identity_before_route_lookup() {
        use crate::agent::sdk::wire::CanonicalWire as _;
        use crate::agent::sdk::*;
        use crate::agent::supervisor_adapters::AgentInvocationRequest;

        let node = VosNode::new();
        let handle = node.ingress_handle();
        let origins = [
            (InvocationOrigin::anonymous(), 503),
            (
                InvocationOrigin {
                    principal: Some(PrincipalId([8; 32])),
                    ..InvocationOrigin::anonymous()
                },
                403,
            ),
            (
                InvocationOrigin {
                    principal: Some(PrincipalId([8; 32])),
                    credential: Some(CredentialId([9; 32])),
                    ..InvocationOrigin::anonymous()
                },
                403,
            ),
            (
                InvocationOrigin {
                    actor: Some(ActorId([8; 32])),
                    ..InvocationOrigin::anonymous()
                },
                403,
            ),
            (
                InvocationOrigin {
                    transport_node: Some(NodeId([8; 32])),
                    ..InvocationOrigin::anonymous()
                },
                403,
            ),
        ];
        for (origin, expected) in origins {
            let work = InvocationWork {
                space: SpaceId([1; 32]),
                agent: AgentId([2; 32]),
                runtime_deployment: DeploymentId([3; 32]),
                invocation: InvocationId([4; 32]),
                actor: ActorId([5; 32]),
                incarnation: Hash([6; 32]),
                deployment: DeploymentId([7; 32]),
                program: ProgramId([8; 32]),
                mode: MethodMode::Query,
                origin,
                roles: InvocationRoleClaims::none(),
                message: vec![1],
                installation_data: None,
                availability: Vec::new(),
                gas: 100,
                recovery_only: false,
            };
            let authorization =
                InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 17));
            let body =
                AgentInvocationRequest::new(RuntimeExecutionContext::Direct, work, authorization)
                    .unwrap()
                    .encode()
                    .unwrap();
            let direct = AgentInvocationRequest::decode(&body).unwrap();
            let work = direct.work();
            let yielded = YieldedInvocation {
                invocation: work.invocation,
                actor: work.actor,
                incarnation: work.incarnation,
                deployment: work.deployment,
                program: work.program,
                mode: work.mode,
                continuation: BlobRef::of_bytes(&[1]),
                ready_sequence: 1,
                installation_data: None,
                required: Vec::new(),
                reason: YieldReason::Cooperative,
            };
            let resume = crate::agent::supervisor_adapters::AgentResumeRequest::new(
                RuntimeExecutionContext::Direct,
                None,
                work.clone(),
                direct.authorization().clone(),
                yielded,
            )
            .unwrap()
            .encode()
            .unwrap();
            let acknowledge = crate::agent::supervisor_adapters::AgentAcknowledgementRequest::new(
                RuntimeExecutionContext::Direct,
                None,
                work.clone(),
                direct.authorization().clone(),
            )
            .unwrap()
            .encode()
            .unwrap();
            for (path, frame) in [
                ("/__agents/resume", resume),
                ("/__agents/acknowledge", acknowledge),
            ] {
                let request = http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(http::header::CONTENT_TYPE, "application/octet-stream")
                    .body(frame.clone())
                    .unwrap();
                assert_eq!(
                    handle_clean_invocation(&request, &handle).status().as_u16(),
                    expected
                );
                let mut truncated = frame.clone();
                truncated.pop();
                let request = http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(http::header::CONTENT_TYPE, "application/octet-stream")
                    .body(truncated)
                    .unwrap();
                assert_eq!(
                    handle_clean_invocation(&request, &handle).status().as_u16(),
                    400
                );
                let wrong_endpoint = http::Request::builder()
                    .method("POST")
                    .uri("/__agents/invoke")
                    .header(http::header::CONTENT_TYPE, "application/octet-stream")
                    .body(frame)
                    .unwrap();
                assert_eq!(
                    handle_clean_invocation(&wrong_endpoint, &handle)
                        .status()
                        .as_u16(),
                    400
                );
                let wrong_frame = http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(http::header::CONTENT_TYPE, "application/octet-stream")
                    .body(body.clone())
                    .unwrap();
                assert_eq!(
                    handle_clean_invocation(&wrong_frame, &handle)
                        .status()
                        .as_u16(),
                    400
                );
            }
            let target =
                crate::agent::supervisor::AgentRouteKey::new(work.space, work.agent, work.actor)
                    .unwrap();
            let intent = crate::agent::supervisor_adapters::AgentInvocationIntent::new(
                work.invocation,
                work.mode,
                work.origin,
                work.roles,
                work.message.clone(),
                work.gas,
                work.recovery_only,
            )
            .unwrap();
            let preparation =
                crate::agent::supervisor_adapters::AgentTargetedPreparationRequest::new(
                    target, intent,
                )
                .unwrap();
            let preparation_request = http::Request::builder()
                .method("POST")
                .uri("/__agents/prepare")
                .header(http::header::CONTENT_TYPE, "application/octet-stream")
                .body(preparation.encode().unwrap())
                .unwrap();
            assert_eq!(
                handle_clean_preparation(&preparation_request, &handle)
                    .status()
                    .as_u16(),
                401
            );
            let attested = AgentInvocationRequest::new(
                RuntimeExecutionContext::Attested {
                    proof_system: Hash([9; 32]),
                },
                direct.work().clone(),
                direct.authorization().clone(),
            )
            .unwrap()
            .encode()
            .unwrap();
            let unsupported = http::Request::builder()
                .method("POST")
                .uri("/__agents/invoke")
                .header(http::header::CONTENT_TYPE, "application/octet-stream")
                .body(attested)
                .unwrap();
            assert_eq!(
                handle_clean_invocation(&unsupported, &handle)
                    .status()
                    .as_u16(),
                501
            );
            let request = http::Request::builder()
                .method("POST")
                .uri("/__agents/invoke")
                .header(http::header::CONTENT_TYPE, "application/octet-stream")
                .body(body.clone())
                .unwrap();
            assert_eq!(
                handle_clean_invocation(&request, &handle).status().as_u16(),
                expected
            );
            // A bearer header must not silently rewrite unsigned request claims.
            let (mut parts, mut malformed) = request.into_parts();
            parts.headers.insert(
                http::header::AUTHORIZATION,
                "Bearer invalid".parse().unwrap(),
            );
            let request = http::Request::from_parts(parts.clone(), malformed.clone());
            assert_eq!(
                handle_clean_invocation(&request, &handle).status().as_u16(),
                expected
            );
            malformed.push(0);
            let request = http::Request::from_parts(parts, malformed);
            assert_eq!(
                handle_clean_invocation(&request, &handle).status().as_u16(),
                400
            );
        }
    }

    fn request(port: u16, path: &str) -> String {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn status_is_anonymous_but_application_routes_require_access() {
        let probe = StdTcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let mut node = VosNode::new();
        node.add_http_ingress(HttpIngressConfig {
            name: "test".into(),
            listen: ([127, 0, 0, 1], port).into(),
            tls: None,
            max_connections: 4,
        })
        .unwrap();

        let status = request(port, "/__status");
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        assert!(status.contains("\"status\":\"ok\""), "{status}");

        let protected = request(port, "/openapi.json");
        assert!(protected.starts_with("HTTP/1.1 401"), "{protected}");

        #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
        {
            let query_method = request(port, "/__agents/credential");
            let ingress = node.ingress_handle();
            ingress.set_clean_agent_recovering_for_test(true);
            for path in [
                "/__status",
                "/",
                "/openapi.json",
                "/__agents/credential",
                "/__agents/invoke",
                "/__agents/prepare",
                "/__agents/local",
                "/__agents/local/install",
                "/__agents/authorize/",
                "/__agents/admin/prepare",
                "/__agents/admin/",
            ] {
                let response = request(port, path);
                assert!(response.starts_with("HTTP/1.1 503"), "{path}: {response}");
            }
            for path in [
                "/__agents/authorize",
                "/__agents/prepare-authorization",
                "/__agents/admin",
            ] {
                let response = request(port, path);
                assert!(response.starts_with("HTTP/1.1 405"), "{path}: {response}");
            }
            ingress.set_clean_agent_recovering_for_test(false);
            assert!(request(port, "/__status").starts_with("HTTP/1.1 200"));
            assert!(query_method.starts_with("HTTP/1.1 405"), "{query_method}");
            let adjacent_query = request(port, "/__agents/credential/");
            assert!(
                adjacent_query.starts_with("HTTP/1.1 401"),
                "{adjacent_query}"
            );
            let inventory = request(port, "/__agents/inventory");
            assert!(inventory.starts_with("HTTP/1.1 405"), "{inventory}");
            let invoke = request(port, "/__agents/invoke");
            assert!(invoke.starts_with("HTTP/1.1 405"), "{invoke}");
            for path in [
                "/__agents/resume",
                "/__agents/acknowledge",
                "/__agents/authorize",
            ] {
                let wrong_method = request(port, path);
                assert!(wrong_method.starts_with("HTTP/1.1 405"), "{wrong_method}");
                let adjacent = request(port, &format!("{path}/"));
                assert!(adjacent.starts_with("HTTP/1.1 401"), "{adjacent}");
            }
            let prepare = request(port, "/__agents/prepare");
            assert!(prepare.starts_with("HTTP/1.1 405"), "{prepare}");
            let adjacent_prepare = request(port, "/__agents/prepare/");
            assert!(
                adjacent_prepare.starts_with("HTTP/1.1 401"),
                "{adjacent_prepare}"
            );
            let adjacent_invoke = request(port, "/__agents/invoke/");
            assert!(
                adjacent_invoke.starts_with("HTTP/1.1 401"),
                "{adjacent_invoke}"
            );
            let adjacent_inventory = request(port, "/__agents/inventory/");
            assert!(
                adjacent_inventory.starts_with("HTTP/1.1 401"),
                "{adjacent_inventory}"
            );
            // The exact lifecycle endpoint uses signed-body authentication;
            // adjacent application paths retain the existing bearer gate.
            let wrong_method = request(port, "/__agents/local");
            assert!(wrong_method.starts_with("HTTP/1.1 405"), "{wrong_method}");
            let adjacent = request(port, "/__agents/local/");
            assert!(adjacent.starts_with("HTTP/1.1 401"), "{adjacent}");
            let wrong_install_method = request(port, "/__agents/local/install");
            assert!(
                wrong_install_method.starts_with("HTTP/1.1 405"),
                "{wrong_install_method}"
            );
            let adjacent_install = request(port, "/__agents/local/install/");
            assert!(
                adjacent_install.starts_with("HTTP/1.1 401"),
                "{adjacent_install}"
            );
            let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            stream
                .write_all(b"POST /__agents/local HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nConnection: close\r\n\r\nLCQ1")
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        }

        let results = node.collect();
        assert!(results.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saturated_blocking_work_cannot_stall_the_status_socket() {
        let node = VosNode::new();
        let handle = node.ingress_handle();
        let blocking = Arc::new(Semaphore::new(2));
        let held = blocking
            .clone()
            .acquire_many_owned(2)
            .await
            .expect("saturate HTTP blocking work");
        let inner = Arc::new(Inner::new(0));
        let (mut client, server) = tokio::io::duplex(4096);
        let serving = tokio::spawn(serve_connection(server, handle, inner, blocking.clone()));

        client
            .write_all(b"GET /__status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_string(&mut response))
            .await
            .expect("I/O workers remain responsive while actor calls are stalled")
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("\"status\":\"ok\""), "{response}");

        drop(held);
        serving.await.unwrap();
        assert!(node.collect().is_empty());
    }
}
