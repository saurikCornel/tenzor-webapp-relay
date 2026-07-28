use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, TcpListener as StdTcpListener,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpSocket, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Instant};
use tokio_rustls::TlsAcceptor;

pub(crate) const PROTOCOL_VERSION: &str = "cornel-web-gateway-connect-v1";

const ENV_PREFIX: &str = "TENZOR_WEBAPP_RELAY_";
const TOKEN_PREFIX: &str = "cwg1";
const PROXY_USERNAME: &str = "cornel";
const GATEWAY_LISTEN_BACKLOG: u32 = 8192;
const MAX_TOKEN_BYTES: usize = 4096;
const MAX_PAYLOAD_BYTES: usize = 2048;
const MAX_DESTINATION_PATTERNS: usize = 32;
const MAX_DESTINATION_SCOPE_BYTES: usize = 1024;
const MAX_RESOLVED_ADDRESSES: usize = 16;
const COPY_BUFFER_BYTES: usize = 16 * 1024;
const MAX_TOKEN_LIFETIME_SECS: u64 = 15 * 60;
const HALF_CLOSE_SHUTDOWN_TIMEOUT_MS: u64 = 500;

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct Config {
    bind: SocketAddrV4,
    listen_bind: SocketAddrV4,
    metrics_bind: SocketAddr,
    gateway_id: String,
    region: String,
    diagnostics_host: String,
    denied_host_suffixes: Vec<String>,
    denied_ips: HashSet<IpAddr>,
    allowed_ports: HashSet<u16>,
    hmac_secret: Arc<[u8]>,
    previous_hmac_secret: Option<Arc<[u8]>>,
    tls_config: Arc<rustls::ServerConfig>,
    tls_handshake_timeout: Duration,
    header_timeout: Duration,
    connect_timeout: Duration,
    idle_timeout: Duration,
    max_header_bytes: usize,
    max_tunnel_bytes: u64,
    max_concurrent: usize,
    max_concurrent_per_sub: usize,
    max_concurrent_per_jti: usize,
    clock_skew_secs: u64,
    max_token_lifetime_secs: u64,
    graceful_drain_timeout: Duration,
}

impl Config {
    pub(crate) fn from_env() -> Result<Option<Self>, String> {
        if !environment_present() {
            return Ok(None);
        }

        let bind = parse_gateway_bind(&required_env("BIND")?)?;
        let listen_bind = match env::var(format!("{ENV_PREFIX}LISTEN_BIND")) {
            Ok(value) => parse_gateway_listen_bind(value.trim())?,
            Err(env::VarError::NotPresent) => bind,
            Err(env::VarError::NotUnicode(_)) => {
                return Err(format!("{ENV_PREFIX}LISTEN_BIND must be valid UTF-8"));
            }
        };
        let metrics_bind = parse_metrics_bind(
            &env::var(format!("{ENV_PREFIX}METRICS_BIND"))
                .unwrap_or_else(|_| "127.0.0.1:9800".to_string()),
        )?;
        let cert_path = required_env("CERT_PEM")?;
        let key_path = required_env("KEY_PEM")?;
        let gateway_id = required_env("ID")?;
        validate_identifier("ID", &gateway_id, 1, 128, b"-_.:")?;
        let region = required_env("REGION")?;
        validate_lower_identifier("REGION", &region, 2, 32, b"-")?;

        let diagnostics_host = normalize_domain(&required_env("DIAGNOSTICS_HOST")?)?;
        let denied_host_suffixes = parse_host_suffixes(&required_env("DENY_HOST_SUFFIXES")?)?;
        if host_matches_any_suffix(&diagnostics_host, &denied_host_suffixes) {
            return Err(
                "DIAGNOSTICS_HOST must not be inside a denied gateway/control suffix".to_string(),
            );
        }
        let denied_ips = parse_denied_ips(&required_env("DENY_IPS")?)?;
        if !denied_ips.contains(&IpAddr::V4(*bind.ip())) {
            return Err("DENY_IPS must include the configured gateway BIND IPv4".to_string());
        }
        let allowed_ports = parse_allowed_ports(
            &env::var(format!("{ENV_PREFIX}ALLOWED_PORTS")).unwrap_or_else(|_| "443".to_string()),
        )?;
        let hmac_secret = Arc::<[u8]>::from(load_hmac_secret()?);
        let previous_hmac_secret =
            load_optional_hmac_secret_file("HMAC_PREVIOUS_SECRET_FILE")?.map(Arc::<[u8]>::from);

        let cert_chain = load_certificate_chain(&cert_path)?;
        let private_key = load_private_key(&key_path)?;
        let tls_config = Arc::new(build_tls_config(cert_chain, private_key)?);

        Ok(Some(Self {
            bind,
            listen_bind,
            metrics_bind,
            gateway_id,
            region,
            diagnostics_host,
            denied_host_suffixes,
            denied_ips,
            allowed_ports,
            hmac_secret,
            previous_hmac_secret,
            tls_config,
            tls_handshake_timeout: Duration::from_millis(env_bounded_u64(
                "TLS_HANDSHAKE_TIMEOUT_MS",
                5_000,
                500,
                15_000,
            )?),
            header_timeout: Duration::from_millis(env_bounded_u64(
                "HEADER_TIMEOUT_MS",
                3_000,
                250,
                10_000,
            )?),
            connect_timeout: Duration::from_millis(env_bounded_u64(
                "CONNECT_TIMEOUT_MS",
                5_000,
                250,
                15_000,
            )?),
            idle_timeout: Duration::from_secs(env_bounded_u64("IDLE_TIMEOUT_SECS", 120, 5, 300)?),
            max_header_bytes: env_bounded_u64("MAX_HEADER_BYTES", 16 * 1024, 1024, 64 * 1024)?
                as usize,
            max_tunnel_bytes: env_bounded_u64(
                "MAX_TUNNEL_BYTES",
                1024 * 1024 * 1024,
                1024 * 1024,
                4 * 1024 * 1024 * 1024,
            )?,
            max_concurrent: env_bounded_u64("MAX_CONCURRENT", 1024, 1, 50_000)? as usize,
            max_concurrent_per_sub: env_bounded_u64("MAX_CONCURRENT_PER_SUB", 64, 1, 1024)?
                as usize,
            max_concurrent_per_jti: env_bounded_u64("MAX_CONCURRENT_PER_JTI", 32, 1, 256)? as usize,
            clock_skew_secs: env_bounded_u64("CLOCK_SKEW_SECS", 15, 0, 30)?,
            max_token_lifetime_secs: env_bounded_u64(
                "MAX_TOKEN_LIFETIME_SECS",
                MAX_TOKEN_LIFETIME_SECS,
                30,
                MAX_TOKEN_LIFETIME_SECS,
            )?,
            graceful_drain_timeout: Duration::from_secs(env_bounded_u64(
                "GRACEFUL_DRAIN_TIMEOUT_SECS",
                30,
                1,
                300,
            )?),
        }))
    }
}

pub(crate) fn environment_present() -> bool {
    env::vars_os().any(|(name, _)| {
        name.to_str()
            .is_some_and(|name| name.starts_with(ENV_PREFIX))
    })
}

fn required_env(suffix: &str) -> Result<String, String> {
    let name = format!("{ENV_PREFIX}{suffix}");
    env::var(&name)
        .map_err(|_| format!("{name} is required when Cornel Web Gateway is enabled"))
        .and_then(|value| {
            let value = value.trim();
            if value.is_empty() {
                Err(format!("{name} must not be empty"))
            } else {
                Ok(value.to_string())
            }
        })
}

/// The public socket clients connect to.
///
/// The address must stay an explicit public IPv4 so a deployment cannot
/// accidentally expose the relay on a wildcard or loopback socket.
///
/// The port is deliberately not pinned to 443. A gateway is a TLS tunnel that
/// carries a burst of connections from one subscriber, and running that burst
/// on 443 is what got 443 itself filtered for the affected networks — taking
/// the platform's own website and API down with it, because they share that
/// port number even though they are a different address entirely. Keeping the
/// port configurable is what stops the next deployment from recreating that.
fn parse_gateway_bind(raw: &str) -> Result<SocketAddrV4, String> {
    let bind = raw.parse::<SocketAddrV4>().map_err(|_| {
        "TENZOR_WEBAPP_RELAY_BIND must be an explicit public IPv4 socket address".to_string()
    })?;
    if !is_public_destination_ipv4(*bind.ip()) {
        return Err("TENZOR_WEBAPP_RELAY_BIND must be an explicit public IPv4 address".to_string());
    }
    if bind.port() == 0 {
        return Err("TENZOR_WEBAPP_RELAY_BIND must name a port".to_string());
    }
    Ok(bind)
}

fn parse_gateway_listen_bind(raw: &str) -> Result<SocketAddrV4, String> {
    let bind = raw.parse::<SocketAddrV4>().map_err(|_| {
        "TENZOR_WEBAPP_RELAY_LISTEN_BIND must be an explicit loopback IPv4 socket address"
            .to_string()
    })?;
    if !bind.ip().is_loopback() || bind.port() < 1024 {
        return Err(
            "TENZOR_WEBAPP_RELAY_LISTEN_BIND must use loopback IPv4 and an unprivileged port"
                .to_string(),
        );
    }
    Ok(bind)
}

fn parse_metrics_bind(raw: &str) -> Result<SocketAddr, String> {
    let bind = raw.parse::<SocketAddr>().map_err(|_| {
        "TENZOR_WEBAPP_RELAY_METRICS_BIND must be a loopback socket address".to_string()
    })?;
    if !bind.ip().is_loopback() || bind.port() == 0 {
        return Err(
            "TENZOR_WEBAPP_RELAY_METRICS_BIND must use loopback and a non-zero port".to_string(),
        );
    }
    Ok(bind)
}

fn env_bounded_u64(suffix: &str, default: u64, min: u64, max: u64) -> Result<u64, String> {
    let name = format!("{ENV_PREFIX}{suffix}");
    let value = match env::var(&name) {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("{name} must be an integer"))?,
        Err(env::VarError::NotPresent) => default,
        Err(env::VarError::NotUnicode(_)) => return Err(format!("{name} must be valid UTF-8")),
    };
    if !(min..=max).contains(&value) {
        return Err(format!("{name} must be between {min} and {max}"));
    }
    Ok(value)
}

fn load_hmac_secret() -> Result<Vec<u8>, String> {
    let direct_name = format!("{ENV_PREFIX}HMAC_SECRET");
    let file_name = format!("{ENV_PREFIX}HMAC_SECRET_FILE");
    let direct = env::var_os(&direct_name);
    let file = env::var_os(&file_name);
    let mut secret = match (direct, file) {
        (Some(_), Some(_)) => {
            return Err(format!(
                "configure exactly one of {direct_name} or {file_name}"
            ));
        }
        (Some(value), None) => value
            .into_string()
            .map_err(|_| format!("{direct_name} must be valid UTF-8"))?
            .into_bytes(),
        (None, Some(path)) => {
            fs::read(path).map_err(|error| format!("failed to read {file_name}: {error}"))?
        }
        (None, None) => {
            return Err(format!("one of {direct_name} or {file_name} is required"));
        }
    };
    while matches!(secret.last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    validate_hmac_secret(&secret)?;
    Ok(secret)
}

fn load_optional_hmac_secret_file(suffix: &str) -> Result<Option<Vec<u8>>, String> {
    let name = format!("{ENV_PREFIX}{suffix}");
    let Some(path) = env::var_os(&name) else {
        return Ok(None);
    };
    if path.is_empty() {
        return Err(format!("{name} must not be empty when configured"));
    }
    let mut secret = fs::read(path).map_err(|error| format!("failed to read {name}: {error}"))?;
    while matches!(secret.last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    validate_hmac_secret(&secret)?;
    Ok(Some(secret))
}

fn validate_hmac_secret(secret: &[u8]) -> Result<(), String> {
    if secret.len() < 32 {
        return Err("Cornel Web Gateway HMAC secret must be at least 32 bytes".to_string());
    }
    if secret.len() > 4096 {
        return Err("Cornel Web Gateway HMAC secret must be at most 4096 bytes".to_string());
    }
    Ok(())
}

fn load_certificate_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = fs::read(path).map_err(|error| format!("failed to read certificate PEM: {error}"))?;
    let certs = rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to parse certificate PEM: {error}"))?;
    if certs.is_empty() {
        return Err("certificate PEM contains no certificates".to_string());
    }
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let pem = fs::read(path).map_err(|error| format!("failed to read private-key PEM: {error}"))?;
    rustls_pemfile::private_key(&mut pem.as_slice())
        .map_err(|error| format!("failed to parse private-key PEM: {error}"))?
        .ok_or_else(|| "private-key PEM contains no private key".to_string())
}

fn build_tls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| format!("invalid TLS protocol configuration: {error}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| format!("invalid TLS identity: {error}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

pub(crate) fn run_dedicated(config: Config, metrics: Arc<Metrics>) -> io::Result<()> {
    let gateway_listener = bind_gateway_listener(SocketAddr::V4(config.listen_bind))?;
    let gateway_bind = gateway_listener.local_addr()?;
    let metrics_listener = StdTcpListener::bind(config.metrics_bind)?;
    metrics_listener.set_nonblocking(true)?;
    let metrics_bind = metrics_listener.local_addr()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("cornel-web-gateway")
        .build()?;

    metrics.enabled.store(true, Ordering::Relaxed);
    metrics.draining.store(false, Ordering::Relaxed);
    eprintln!(
        "Cornel Web Gateway listening on https://{gateway_bind} public_identity={} protocol={PROTOCOL_VERSION}",
        config.bind
    );
    eprintln!("Cornel Web Gateway health and metrics listening on http://{metrics_bind}");
    runtime.block_on(run_dedicated_async(
        gateway_listener,
        metrics_listener,
        Arc::new(config),
        metrics,
    ))
}

async fn run_dedicated_async(
    gateway_listener: StdTcpListener,
    metrics_listener: StdTcpListener,
    config: Arc<Config>,
    metrics: Arc<Metrics>,
) -> io::Result<()> {
    let (gateway_shutdown_tx, gateway_shutdown_rx) = watch::channel(false);
    let (metrics_shutdown_tx, metrics_shutdown_rx) = watch::channel(false);
    let mut gateway_task = tokio::spawn(serve_gateway(
        gateway_listener,
        config.clone(),
        metrics.clone(),
        gateway_shutdown_rx,
    ));
    let mut metrics_task = tokio::spawn(serve_local_metrics(
        metrics_listener,
        metrics.clone(),
        metrics_shutdown_rx,
    ));

    enum RunEvent {
        Shutdown(io::Result<()>),
        Gateway(Result<io::Result<()>, tokio::task::JoinError>),
        Metrics(Result<io::Result<()>, tokio::task::JoinError>),
    }

    let event = tokio::select! {
        result = &mut gateway_task => {
            RunEvent::Gateway(result)
        }
        result = &mut metrics_task => {
            RunEvent::Metrics(result)
        }
        signal = wait_for_shutdown_signal() => {
            RunEvent::Shutdown(signal)
        }
    };
    match event {
        RunEvent::Gateway(result) => {
            mark_draining(&metrics);
            let _ = metrics_shutdown_tx.send(true);
            metrics_task.abort();
            let _ = metrics_task.await;
            return listener_task_ended("gateway", result);
        }
        RunEvent::Metrics(result) => {
            mark_draining(&metrics);
            let _ = gateway_shutdown_tx.send(true);
            gateway_task.abort();
            let _ = gateway_task.await;
            return listener_task_ended("health/metrics", result);
        }
        RunEvent::Shutdown(signal) => {
            signal?;
            mark_draining(&metrics);
            eprintln!(
                "Cornel Web Gateway shutdown requested; draining {} active connection(s)",
                metrics.active_connections.load(Ordering::Relaxed)
            );
            let _ = gateway_shutdown_tx.send(true);
        }
    }

    match gateway_task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            let _ = metrics_shutdown_tx.send(true);
            metrics_task.abort();
            return Err(io::Error::new(
                error.kind(),
                format!("gateway listener failed during shutdown: {error}"),
            ));
        }
        Err(error) => {
            let _ = metrics_shutdown_tx.send(true);
            metrics_task.abort();
            return Err(io::Error::other(format!(
                "gateway listener task failed during shutdown: {error}"
            )));
        }
    }

    let drained = tokio::select! {
        result = &mut metrics_task => {
            return listener_task_ended("health/metrics", result);
        }
        result = timeout(config.graceful_drain_timeout, wait_until_drained(metrics.clone())) => {
            result.is_ok()
        }
    };
    if drained {
        eprintln!("Cornel Web Gateway drain complete");
    } else {
        eprintln!(
            "Cornel Web Gateway drain timeout reached with {} active connection(s); forcing exit",
            metrics.active_connections.load(Ordering::Relaxed)
        );
    }

    let _ = metrics_shutdown_tx.send(true);
    match metrics_task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(io::Error::new(
            error.kind(),
            format!("health/metrics listener failed during shutdown: {error}"),
        )),
        Err(error) => Err(io::Error::other(format!(
            "health/metrics listener task failed during shutdown: {error}"
        ))),
    }
}

fn mark_draining(metrics: &Metrics) {
    metrics.draining.store(true, Ordering::Relaxed);
    metrics.ready.store(false, Ordering::Relaxed);
}

async fn wait_until_drained(metrics: Arc<Metrics>) {
    while !metrics.is_drained() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn listener_task_ended(
    name: &str,
    result: Result<io::Result<()>, tokio::task::JoinError>,
) -> io::Result<()> {
    match result {
        Ok(Ok(())) => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("{name} listener stopped unexpectedly"),
        )),
        Ok(Err(error)) => Err(io::Error::new(
            error.kind(),
            format!("{name} listener failed: {error}"),
        )),
        Err(error) => Err(io::Error::other(format!(
            "{name} listener task failed: {error}"
        ))),
    }
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> io::Result<()> {
    tokio::signal::ctrl_c().await
}

const LOCAL_METRICS_MAX_HEADER_BYTES: usize = 8 * 1024;
const LOCAL_METRICS_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalMetricsRequestKind {
    Metrics,
    Health,
    Ready,
    NotFound,
    BadRequest,
}

fn local_metrics_request_kind(first_line: &str) -> LocalMetricsRequestKind {
    let mut parts = first_line.split_whitespace();
    let method = parts.next();
    let target = parts.next();
    let version = parts.next();
    if parts.next().is_some() || method != Some("GET") || version != Some("HTTP/1.1") {
        return LocalMetricsRequestKind::BadRequest;
    }
    match target {
        Some("/") | Some("/metrics") => LocalMetricsRequestKind::Metrics,
        Some("/healthz") => LocalMetricsRequestKind::Health,
        Some("/readyz") => LocalMetricsRequestKind::Ready,
        _ => LocalMetricsRequestKind::NotFound,
    }
}

async fn serve_local_metrics(
    listener: StdTcpListener,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let listener = TcpListener::from_std(listener)?;
    loop {
        let accepted = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if *shutdown.borrow() => return Ok(()),
                    Err(_) => return Ok(()),
                    Ok(()) => continue,
                }
            }
            accepted = listener.accept() => accepted,
        };
        let (stream, _) = accepted?;
        let metrics = metrics.clone();
        tokio::spawn(async move {
            respond_local_metrics(stream, metrics).await;
        });
    }
}

async fn respond_local_metrics(mut stream: TcpStream, metrics: Arc<Metrics>) {
    let first_line = match timeout(
        LOCAL_METRICS_REQUEST_TIMEOUT,
        read_local_metrics_first_line(&mut stream),
    )
    .await
    {
        Ok(Ok(first_line)) => first_line,
        Ok(Err(_)) | Err(_) => {
            let _ = write_local_json_response(
                &mut stream,
                400,
                serde_json::json!({ "ok": false, "error": "bad request" }).to_string(),
            )
            .await;
            return;
        }
    };

    let (status, content_type, body) = match local_metrics_request_kind(&first_line) {
        LocalMetricsRequestKind::Health => (
            200,
            "application/json",
            serde_json::json!({ "ok": true }).to_string(),
        ),
        LocalMetricsRequestKind::Ready => {
            let ready = metrics.required_ready();
            (
                if ready { 200 } else { 503 },
                "application/json",
                serde_json::json!({
                    "ok": ready,
                    "web_gateway": metrics.snapshot(),
                })
                .to_string(),
            )
        }
        LocalMetricsRequestKind::Metrics => (
            200,
            "text/plain; version=0.0.4",
            render_prometheus_metrics(&metrics),
        ),
        LocalMetricsRequestKind::NotFound => (
            404,
            "application/json",
            serde_json::json!({ "ok": false, "error": "not found" }).to_string(),
        ),
        LocalMetricsRequestKind::BadRequest => (
            400,
            "application/json",
            serde_json::json!({ "ok": false, "error": "bad request" }).to_string(),
        ),
    };
    let _ = write_local_response(&mut stream, status, content_type, body).await;
}

fn render_prometheus_metrics(metrics: &Metrics) -> String {
    let snapshot = metrics.snapshot();
    format!(
        concat!(
            "# TYPE cornel_web_gateway_ready gauge\n",
            "cornel_web_gateway_ready {}\n",
            "# TYPE cornel_web_gateway_draining gauge\n",
            "cornel_web_gateway_draining {}\n",
            "# TYPE cornel_web_gateway_active_connections gauge\n",
            "cornel_web_gateway_active_connections {}\n",
            "# TYPE cornel_web_gateway_active_tunnels gauge\n",
            "cornel_web_gateway_active_tunnels {}\n",
            "# TYPE cornel_web_gateway_accepted_connections_total counter\n",
            "cornel_web_gateway_accepted_connections_total {}\n",
            "# TYPE cornel_web_gateway_tls_failures_total counter\n",
            "cornel_web_gateway_tls_failures_total {}\n",
            "# TYPE cornel_web_gateway_parse_failures_total counter\n",
            "cornel_web_gateway_parse_failures_total {}\n",
            "# TYPE cornel_web_gateway_auth_failures_total counter\n",
            "cornel_web_gateway_auth_failures_total {}\n",
            "# TYPE cornel_web_gateway_policy_denied_total counter\n",
            "cornel_web_gateway_policy_denied_total {}\n",
            "# TYPE cornel_web_gateway_dns_failures_total counter\n",
            "cornel_web_gateway_dns_failures_total {}\n",
            "# TYPE cornel_web_gateway_connect_failures_total counter\n",
            "cornel_web_gateway_connect_failures_total {}\n",
            "# TYPE cornel_web_gateway_concurrency_rejected_total counter\n",
            "cornel_web_gateway_concurrency_rejected_total {}\n",
            "# TYPE cornel_web_gateway_tunnels_established_total counter\n",
            "cornel_web_gateway_tunnels_established_total {}\n",
            "# TYPE cornel_web_gateway_tunnels_completed_total counter\n",
            "cornel_web_gateway_tunnels_completed_total {}\n",
            "# TYPE cornel_web_gateway_bytes_up_total counter\n",
            "cornel_web_gateway_bytes_up_total {}\n",
            "# TYPE cornel_web_gateway_bytes_down_total counter\n",
            "cornel_web_gateway_bytes_down_total {}\n",
            "# TYPE cornel_web_gateway_idle_timeouts_total counter\n",
            "cornel_web_gateway_idle_timeouts_total {}\n",
            "# TYPE cornel_web_gateway_byte_limit_exceeded_total counter\n",
            "cornel_web_gateway_byte_limit_exceeded_total {}\n",
            "# TYPE cornel_web_gateway_token_expirations_total counter\n",
            "cornel_web_gateway_token_expirations_total {}\n",
            "# TYPE cornel_web_gateway_tunnel_errors_total counter\n",
            "cornel_web_gateway_tunnel_errors_total {}\n"
        ),
        u8::from(snapshot.ready && !snapshot.draining),
        u8::from(snapshot.draining),
        snapshot.active_connections,
        snapshot.active_tunnels,
        snapshot.accepted_connections,
        snapshot.tls_failures,
        snapshot.parse_failures,
        snapshot.auth_failures,
        snapshot.policy_denied,
        snapshot.dns_failures,
        snapshot.connect_failures,
        snapshot.concurrency_rejected,
        snapshot.tunnels_established,
        snapshot.tunnels_completed,
        snapshot.bytes_up,
        snapshot.bytes_down,
        snapshot.idle_timeouts,
        snapshot.byte_limit_exceeded,
        snapshot.token_expirations,
        snapshot.tunnel_errors,
    )
}

async fn read_local_metrics_first_line(stream: &mut TcpStream) -> io::Result<String> {
    let mut request = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before request headers",
            ));
        }
        request.extend_from_slice(&buffer[..count]);
        if let Some(header_end) = find_header_end(&request) {
            if header_end + 4 > LOCAL_METRICS_MAX_HEADER_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request headers exceed configured limit",
                ));
            }
            let header = std::str::from_utf8(&request[..header_end]).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "request headers are not UTF-8")
            })?;
            return Ok(header.lines().next().unwrap_or_default().to_string());
        }
        if request.len() >= LOCAL_METRICS_MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers exceed configured limit",
            ));
        }
    }
}

async fn write_local_json_response(
    stream: &mut TcpStream,
    status: u16,
    body: String,
) -> io::Result<()> {
    write_local_response(stream, status, "application/json", body).await
}

async fn write_local_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: String,
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    timeout(
        LOCAL_METRICS_REQUEST_TIMEOUT,
        stream.write_all(response.as_bytes()),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "metrics response timed out"))??;
    Ok(())
}

async fn serve_gateway(
    listener: StdTcpListener,
    config: Arc<Config>,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let listener = TcpListener::from_std(listener)?;
    let _readiness = GatewayReadinessGuard::new(metrics.clone());
    let acceptor = TlsAcceptor::from(config.tls_config.clone());
    let concurrency = Arc::new(Semaphore::new(config.max_concurrent));
    let quotas = Arc::new(QuotaState::default());

    loop {
        let accepted = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if *shutdown.borrow() => return Ok(()),
                    Err(_) => return Ok(()),
                    Ok(()) => continue,
                }
            }
            accepted = listener.accept() => accepted,
        };
        let (stream, _) = accepted?;
        let request_id = metrics
            .accepted_connections
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let active_connection = ActiveConnectionGuard::new(metrics.clone());
        let permit = match concurrency.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                metrics.concurrency_rejected.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "service=cornel_web_gateway event=connection_closed request_id={request_id} outcome=global_concurrency_rejected duration_ms=0"
                );
                drop(stream);
                continue;
            }
        };
        let config = config.clone();
        let metrics = metrics.clone();
        let quotas = quotas.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _active_connection = active_connection;
            handle_connection(
                request_id, stream, acceptor, config, metrics, quotas, permit,
            )
            .await;
        });
    }
}

fn bind_gateway_listener(address: SocketAddr) -> io::Result<StdTcpListener> {
    let domain = match address {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(GATEWAY_LISTEN_BACKLOG as i32)?;
    Ok(socket.into())
}

struct GatewayReadinessGuard {
    metrics: Arc<Metrics>,
}

impl GatewayReadinessGuard {
    fn new(metrics: Arc<Metrics>) -> Self {
        metrics.ready.store(true, Ordering::Relaxed);
        Self { metrics }
    }
}

impl Drop for GatewayReadinessGuard {
    fn drop(&mut self) {
        self.metrics.ready.store(false, Ordering::Relaxed);
    }
}

async fn handle_connection(
    request_id: u64,
    stream: TcpStream,
    acceptor: TlsAcceptor,
    config: Arc<Config>,
    metrics: Arc<Metrics>,
    quotas: Arc<QuotaState>,
    _permit: OwnedSemaphorePermit,
) {
    let mut request_log = ConnectionLogGuard::new(request_id);
    let metrics = metrics.as_ref();
    let mut tls = match timeout(config.tls_handshake_timeout, acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(_)) | Err(_) => {
            metrics.tls_failures.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("tls_failure");
            return;
        }
    };

    let request_bytes = match timeout(
        config.header_timeout,
        read_connect_header(&mut tls, config.max_header_bytes),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) | Err(_) => {
            metrics.parse_failures.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("header_failure");
            let _ = write_proxy_response(&mut tls, 400, config.header_timeout).await;
            return;
        }
    };

    let request = match parse_connect_request(&request_bytes, &config.allowed_ports) {
        Ok(request) => request,
        Err(RequestError::Authentication) => {
            metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("proxy_auth_missing");
            let _ = write_proxy_response(&mut tls, 407, config.header_timeout).await;
            return;
        }
        Err(RequestError::BadRequest) => {
            metrics.parse_failures.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("request_invalid");
            let _ = write_proxy_response(&mut tls, 400, config.header_timeout).await;
            return;
        }
        Err(RequestError::Policy) => {
            metrics.policy_denied.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("port_or_authority_denied");
            let _ = write_proxy_response(&mut tls, 403, config.header_timeout).await;
            return;
        }
    };
    request_log.set_target(request.host.clone(), request.port);

    let now_unix = unix_time_secs();
    let claims = match verify_token(&request.token, &config, now_unix) {
        Ok(claims) => claims,
        Err(_) => {
            metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("token_invalid");
            let _ = write_proxy_response(&mut tls, 407, config.header_timeout).await;
            return;
        }
    };

    if request.host != config.diagnostics_host
        && !destination_scope_matches(&request.host, &claims.dst)
    {
        metrics.policy_denied.fetch_add(1, Ordering::Relaxed);
        request_log.set_outcome("destination_scope_denied");
        let _ = write_proxy_response(&mut tls, 403, config.header_timeout).await;
        return;
    }

    if is_denied_host(
        &request.host,
        &config.diagnostics_host,
        &config.denied_host_suffixes,
    ) {
        metrics.policy_denied.fetch_add(1, Ordering::Relaxed);
        request_log.set_outcome("destination_host_denied");
        let _ = write_proxy_response(&mut tls, 403, config.header_timeout).await;
        return;
    }

    let _quota = match quotas.acquire(
        &claims.sub,
        &claims.jti,
        config.max_concurrent_per_sub,
        config.max_concurrent_per_jti,
    ) {
        Some(guard) => guard,
        None => {
            metrics.concurrency_rejected.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("subject_concurrency_rejected");
            let _ = write_proxy_response(&mut tls, 429, config.header_timeout).await;
            return;
        }
    };

    let upstream = match resolve_and_connect(&request.host, request.port, &config).await {
        Ok(upstream) => upstream,
        Err(ConnectError::Policy) => {
            metrics.policy_denied.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("destination_ip_denied");
            let _ = write_proxy_response(&mut tls, 403, config.header_timeout).await;
            return;
        }
        Err(ConnectError::Dns) => {
            metrics.dns_failures.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("dns_failure");
            let _ = write_proxy_response(&mut tls, 502, config.header_timeout).await;
            return;
        }
        Err(ConnectError::Connect) => {
            metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("upstream_connect_failure");
            let _ = write_proxy_response(&mut tls, 502, config.header_timeout).await;
            return;
        }
    };

    if claims.exp <= unix_time_secs() {
        metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        request_log.set_outcome("token_expired_before_connect");
        let _ = write_proxy_response(&mut tls, 407, config.header_timeout).await;
        return;
    }
    if write_proxy_response(&mut tls, 200, config.header_timeout)
        .await
        .is_err()
    {
        request_log.set_outcome("client_closed_before_connect");
        return;
    }

    metrics.tunnels_established.fetch_add(1, Ordering::Relaxed);
    let _active = ActiveTunnelGuard::new(metrics);
    let outcome = pump_tunnel(
        tls,
        upstream,
        request.initial_tunnel_data,
        claims.exp,
        &config,
        metrics,
    )
    .await;
    match outcome {
        PumpOutcome::Completed => {
            metrics.tunnels_completed.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("completed");
        }
        PumpOutcome::IdleTimeout => {
            metrics.idle_timeouts.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("idle_timeout");
        }
        PumpOutcome::ByteLimit => {
            metrics.byte_limit_exceeded.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("byte_limit");
        }
        PumpOutcome::TokenExpired => {
            metrics.token_expirations.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("token_expired");
        }
        PumpOutcome::IoError => {
            metrics.tunnel_errors.fetch_add(1, Ordering::Relaxed);
            request_log.set_outcome("io_error");
        }
    }
}

struct ConnectionLogGuard {
    request_id: u64,
    started: Instant,
    outcome: &'static str,
    target: Option<(String, u16)>,
}

impl ConnectionLogGuard {
    fn new(request_id: u64) -> Self {
        Self {
            request_id,
            started: Instant::now(),
            outcome: "connection_dropped",
            target: None,
        }
    }

    fn set_outcome(&mut self, outcome: &'static str) {
        self.outcome = outcome;
    }

    fn set_target(&mut self, host: String, port: u16) {
        self.target = Some((host, port));
    }
}

impl Drop for ConnectionLogGuard {
    fn drop(&mut self) {
        if let Some((host, port)) = &self.target {
            eprintln!(
                "service=cornel_web_gateway event=connection_closed request_id={} outcome={} target={}:{} duration_ms={}",
                self.request_id,
                self.outcome,
                host,
                port,
                self.started.elapsed().as_millis(),
            );
        } else {
            eprintln!(
                "service=cornel_web_gateway event=connection_closed request_id={} outcome={} duration_ms={}",
                self.request_id,
                self.outcome,
                self.started.elapsed().as_millis(),
            );
        }
    }
}

struct ConnectRequest {
    host: String,
    port: u16,
    token: String,
    initial_tunnel_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestError {
    BadRequest,
    Authentication,
    Policy,
}

async fn read_connect_header<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_header_bytes: usize,
) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(max_header_bytes.min(4096));
    let mut chunk = [0_u8; 4096];
    loop {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before CONNECT headers",
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(header_end) = find_header_end(&bytes) {
            if header_end + 4 > max_header_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "CONNECT headers exceed configured limit",
                ));
            }
            return Ok(bytes);
        }
        if bytes.len() >= max_header_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CONNECT headers exceed configured limit",
            ));
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_connect_request(
    bytes: &[u8],
    allowed_ports: &HashSet<u16>,
) -> Result<ConnectRequest, RequestError> {
    let header_end = find_header_end(bytes).ok_or(RequestError::BadRequest)?;
    let header = std::str::from_utf8(&bytes[..header_end]).map_err(|_| RequestError::BadRequest)?;
    if header
        .as_bytes()
        .iter()
        .any(|byte| (*byte < 0x20 && !matches!(*byte, b'\r' | b'\n')) || *byte == 0x7f)
    {
        return Err(RequestError::BadRequest);
    }
    let lines = header.split("\r\n").collect::<Vec<_>>();
    if lines.is_empty() || lines.len() > 65 {
        return Err(RequestError::BadRequest);
    }
    if lines
        .iter()
        .any(|line| line.contains(['\r', '\n']) || line.len() > 4096)
    {
        return Err(RequestError::BadRequest);
    }

    let request_parts = lines[0].split(' ').collect::<Vec<_>>();
    if request_parts.len() != 3
        || request_parts[0] != "CONNECT"
        || request_parts[2] != "HTTP/1.1"
        || request_parts.iter().any(|part| part.is_empty())
    {
        return Err(RequestError::BadRequest);
    }
    let (host, port) = parse_authority(request_parts[1])?;
    if !allowed_ports.contains(&port) {
        return Err(RequestError::Policy);
    }

    let mut host_header = None;
    let mut proxy_authorization = None;
    for line in &lines[1..] {
        if line.is_empty() || line.starts_with([' ', '\t']) {
            return Err(RequestError::BadRequest);
        }
        let (name, value) = line.split_once(':').ok_or(RequestError::BadRequest)?;
        if !is_http_token(name.as_bytes()) {
            return Err(RequestError::BadRequest);
        }
        let value = value.trim_matches([' ', '\t']);
        if value.is_empty()
            || value
                .as_bytes()
                .iter()
                .any(|byte| *byte < 0x20 || *byte == 0x7f)
        {
            return Err(RequestError::BadRequest);
        }
        if name.eq_ignore_ascii_case("host") {
            if host_header.replace(value).is_some() {
                return Err(RequestError::BadRequest);
            }
        } else if name.eq_ignore_ascii_case("proxy-authorization") {
            if proxy_authorization.replace(value).is_some() {
                return Err(RequestError::Authentication);
            }
        } else if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            return Err(RequestError::BadRequest);
        }
    }

    let host_header = host_header.ok_or(RequestError::BadRequest)?;
    let (header_host, header_port) = parse_authority(host_header)?;
    if header_host != host || header_port != port {
        return Err(RequestError::BadRequest);
    }

    let authorization = proxy_authorization.ok_or(RequestError::Authentication)?;
    let (scheme, encoded) = authorization
        .split_once(' ')
        .ok_or(RequestError::Authentication)?;
    if !scheme.eq_ignore_ascii_case("basic") || encoded.is_empty() || encoded.len() > 6144 {
        return Err(RequestError::Authentication);
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| RequestError::Authentication)?;
    let credentials = std::str::from_utf8(&decoded).map_err(|_| RequestError::Authentication)?;
    let (username, token) = credentials
        .split_once(':')
        .ok_or(RequestError::Authentication)?;
    if username != PROXY_USERNAME
        || token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || token.contains(':')
    {
        return Err(RequestError::Authentication);
    }

    Ok(ConnectRequest {
        host,
        port,
        token: token.to_string(),
        initial_tunnel_data: bytes[header_end + 4..].to_vec(),
    })
}

fn is_http_token(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    *byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn parse_authority(authority: &str) -> Result<(String, u16), RequestError> {
    if authority.is_empty()
        || authority.len() > 512
        || authority.contains(['/', '\\', '@', '?', '#'])
        || !authority.is_ascii()
    {
        return Err(RequestError::BadRequest);
    }
    if authority.starts_with('[') || authority.contains(']') {
        // IP literals are deliberately unsupported: a hostname is required so
        // configured control/gateway suffix policy cannot be bypassed.
        return Err(RequestError::Policy);
    }
    let (host, port) = authority.rsplit_once(':').ok_or(RequestError::BadRequest)?;
    if host.contains(':') || host.parse::<IpAddr>().is_ok() {
        return Err(RequestError::Policy);
    }
    let host = normalize_domain(host).map_err(|_| RequestError::BadRequest)?;
    let port = port.parse::<u16>().map_err(|_| RequestError::BadRequest)?;
    if port == 0 {
        return Err(RequestError::BadRequest);
    }
    Ok((host, port))
}

fn normalize_domain(raw: &str) -> Result<String, String> {
    let host = raw.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || !host.contains('.')
        || host.contains("..")
    {
        return Err("host must be a fully-qualified ASCII domain".to_string());
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err("host contains an invalid DNS label".to_string());
        }
    }
    Ok(host)
}

fn parse_host_suffixes(raw: &str) -> Result<Vec<String>, String> {
    let mut suffixes = Vec::new();
    for value in raw.split(',') {
        let value = value
            .trim()
            .trim_start_matches("*.")
            .trim_start_matches('.');
        if value.is_empty() {
            continue;
        }
        suffixes.push(normalize_domain(value)?);
    }
    suffixes.sort();
    suffixes.dedup();
    if suffixes.is_empty() {
        return Err("DENY_HOST_SUFFIXES must include gateway/control host suffixes".to_string());
    }
    Ok(suffixes)
}

fn is_denied_host(host: &str, diagnostics_host: &str, denied_suffixes: &[String]) -> bool {
    if host == diagnostics_host {
        return false;
    }
    host_matches_any_suffix(host, denied_suffixes)
}

fn host_matches_any_suffix(host: &str, denied_suffixes: &[String]) -> bool {
    denied_suffixes
        .iter()
        .any(|suffix| host == suffix || host.ends_with(&format!(".{suffix}")))
}

fn parse_allowed_ports(raw: &str) -> Result<HashSet<u16>, String> {
    let ports = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<u16>()
                .ok()
                .filter(|port| *port > 0)
                .ok_or_else(|| format!("invalid allowed destination port: {value}"))
        })
        .collect::<Result<HashSet<_>, _>>()?;
    if ports.is_empty() || ports.len() > 16 {
        return Err("ALLOWED_PORTS must contain between 1 and 16 ports".to_string());
    }
    Ok(ports)
}

fn parse_denied_ips(raw: &str) -> Result<HashSet<IpAddr>, String> {
    let ips = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|_| format!("invalid denied IP address: {value}"))
        })
        .collect::<Result<HashSet<_>, _>>()?;
    if ips.is_empty() || ips.len() > 64 {
        return Err(
            "DENY_IPS must contain the public gateway IP and at most 64 entries".to_string(),
        );
    }
    if ips.iter().any(|ip| !is_public_destination_ip(*ip)) {
        return Err("DENY_IPS entries must be public IP addresses".to_string());
    }
    Ok(ips)
}

fn validate_identifier(
    name: &str,
    value: &str,
    min: usize,
    max: usize,
    extra: &[u8],
) -> Result<(), String> {
    if value.len() < min
        || value.len() > max
        || !value.is_ascii()
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(byte))
    {
        return Err(format!("WEB_GATEWAY_{name} has invalid syntax"));
    }
    Ok(())
}

fn validate_lower_identifier(
    name: &str,
    value: &str,
    min: usize,
    max: usize,
    extra: &[u8],
) -> Result<(), String> {
    if value.len() < min
        || value.len() > max
        || !value.is_ascii()
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || extra.contains(byte))
    {
        return Err(format!("WEB_GATEWAY_{name} has invalid syntax"));
    }
    Ok(())
}

async fn write_proxy_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    write_timeout: Duration,
) -> io::Result<()> {
    let response: &[u8] = match status {
        200 => b"HTTP/1.1 200 Connection Established\r\nConnection: keep-alive\r\n\r\n",
        400 => b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        403 => b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        407 => b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Cornel Web Gateway\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        429 => b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        _ => b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    };
    timeout(write_timeout, stream.write_all(response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy response timed out"))??;
    timeout(write_timeout, stream.flush())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy flush timed out"))??;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenClaims {
    v: u8,
    aud: String,
    sub: String,
    jti: String,
    iat: i64,
    exp: i64,
    region: String,
    app: String,
    dst: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenError {
    Invalid,
    Expired,
}

fn verify_token(token: &str, config: &Config, now_unix: i64) -> Result<TokenClaims, TokenError> {
    if token.len() > MAX_TOKEN_BYTES || !token.is_ascii() {
        return Err(TokenError::Invalid);
    }
    let mut parts = token.split('.');
    let version = parts.next().ok_or(TokenError::Invalid)?;
    let payload_b64 = parts.next().ok_or(TokenError::Invalid)?;
    let signature_b64 = parts.next().ok_or(TokenError::Invalid)?;
    if version != TOKEN_PREFIX || parts.next().is_some() || payload_b64.len() > 3072 {
        return Err(TokenError::Invalid);
    }

    let signature = decode_canonical_base64url(signature_b64, 32, 32)?;
    let current_valid =
        token_signature_matches(&config.hmac_secret, payload_b64.as_bytes(), &signature)?;
    // Always perform a second HMAC verification. During rotation this accepts
    // the previous key; outside rotation it repeats with the current key so
    // key-overlap configuration is not exposed through a timing branch.
    let previous_key = config
        .previous_hmac_secret
        .as_deref()
        .unwrap_or(&config.hmac_secret);
    let previous_valid = token_signature_matches(previous_key, payload_b64.as_bytes(), &signature)?;
    if !(current_valid | previous_valid) {
        return Err(TokenError::Invalid);
    }

    let payload = decode_canonical_base64url(payload_b64, 2, MAX_PAYLOAD_BYTES)?;
    let claims =
        serde_json::from_slice::<TokenClaims>(&payload).map_err(|_| TokenError::Invalid)?;
    validate_claims(&claims, config, now_unix)?;
    Ok(claims)
}

fn token_signature_matches(
    secret: &[u8],
    payload_b64: &[u8],
    signature: &[u8],
) -> Result<bool, TokenError> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| TokenError::Invalid)?;
    mac.update(TOKEN_PREFIX.as_bytes());
    mac.update(b".");
    mac.update(payload_b64);
    Ok(mac.verify_slice(signature).is_ok())
}

fn validate_claims(claims: &TokenClaims, config: &Config, now_unix: i64) -> Result<(), TokenError> {
    if claims.v != 1 || claims.aud != config.gateway_id || claims.region != config.region {
        return Err(TokenError::Invalid);
    }
    if claims.iat < 0 || claims.exp < 0 || claims.exp <= claims.iat {
        return Err(TokenError::Invalid);
    }
    if claims.exp <= now_unix {
        return Err(TokenError::Expired);
    }
    let skew = config.clock_skew_secs as i64;
    if claims.iat > now_unix.saturating_add(skew) {
        return Err(TokenError::Invalid);
    }
    let lifetime = claims
        .exp
        .checked_sub(claims.iat)
        .ok_or(TokenError::Invalid)?;
    if lifetime > config.max_token_lifetime_secs as i64 {
        return Err(TokenError::Invalid);
    }
    validate_base64url_claim(&claims.sub, 16, 64)?;
    validate_base64url_claim(&claims.jti, 16, 16)?;
    validate_claim_identifier(&claims.region, 2, 32, b"-")?;
    validate_claim_identifier(&claims.app, 1, 64, b"-_")?;
    validate_destination_scope(&claims.dst)?;
    Ok(())
}

fn validate_destination_scope(patterns: &[String]) -> Result<(), TokenError> {
    if patterns.is_empty() || patterns.len() > MAX_DESTINATION_PATTERNS {
        return Err(TokenError::Invalid);
    }
    let mut total_bytes = 0_usize;
    let mut unique = HashSet::with_capacity(patterns.len());
    for pattern in patterns {
        total_bytes = total_bytes
            .checked_add(pattern.len())
            .ok_or(TokenError::Invalid)?;
        if total_bytes > MAX_DESTINATION_SCOPE_BYTES || !unique.insert(pattern.as_str()) {
            return Err(TokenError::Invalid);
        }
        let domain = pattern.strip_prefix("*.").unwrap_or(pattern);
        let normalized = normalize_domain(domain).map_err(|_| TokenError::Invalid)?;
        if normalized != domain || (pattern.contains('*') && !pattern.starts_with("*.")) {
            return Err(TokenError::Invalid);
        }
    }
    Ok(())
}

fn destination_scope_matches(host: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            host == suffix || host.ends_with(&format!(".{suffix}"))
        } else {
            host == pattern
        }
    })
}

fn validate_base64url_claim(value: &str, min: usize, max: usize) -> Result<(), TokenError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| TokenError::Invalid)?;
    if decoded.len() < min || decoded.len() > max || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(TokenError::Invalid);
    }
    Ok(())
}

fn validate_claim_identifier(
    value: &str,
    min: usize,
    max: usize,
    extra: &[u8],
) -> Result<(), TokenError> {
    if value.len() < min
        || value.len() > max
        || !value.is_ascii()
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || extra.contains(byte))
    {
        return Err(TokenError::Invalid);
    }
    Ok(())
}

fn decode_canonical_base64url(value: &str, min: usize, max: usize) -> Result<Vec<u8>, TokenError> {
    if value.is_empty() || value.contains('=') || !value.is_ascii() {
        return Err(TokenError::Invalid);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| TokenError::Invalid)?;
    if decoded.len() < min || decoded.len() > max || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(TokenError::Invalid);
    }
    Ok(decoded)
}

fn unix_time_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectError {
    Dns,
    Policy,
    Connect,
}

async fn resolve_and_connect(
    host: &str,
    port: u16,
    config: &Config,
) -> Result<TcpStream, ConnectError> {
    let deadline = Instant::now() + config.connect_timeout;
    // A trailing dot forces an absolute DNS query and prevents libc resolver
    // search-domain/ndots expansion from changing the policy-checked name.
    let absolute_host = format!("{host}.");
    let resolved = timeout(
        config.connect_timeout,
        lookup_host((absolute_host.as_str(), port)),
    )
    .await
    .map_err(|_| ConnectError::Dns)?
    .map_err(|_| ConnectError::Dns)?;
    let mut addresses = Vec::new();
    for address in resolved {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        return Err(ConnectError::Dns);
    }

    // This deployment contract has an explicit dedicated IPv4 but no
    // dedicated IPv6 source. Real CDNs often return large, rotating mixed
    // A/AAAA sets; rejecting the entire DNS answer because one candidate is
    // IPv6, denied or otherwise non-routable makes valid Web Apps randomly
    // fail. Select only safe public IPv4 candidates and fail closed if none
    // exist. Private, special-use and explicitly denied addresses are never
    // dialed.
    let addresses = dedicated_ipv4_egress_addresses(addresses, &config.denied_ips);
    if addresses.is_empty() {
        return Err(ConnectError::Policy);
    }
    let address_count = addresses.len();
    for (index, address) in addresses.into_iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let attempts_left = (address_count - index).max(1) as u32;
        let attempt_timeout = remaining / attempts_left;
        match timeout(
            attempt_timeout,
            connect_from_gateway_ipv4(*config.bind.ip(), address),
        )
        .await
        {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(_)) | Err(_) => continue,
        }
    }
    Err(ConnectError::Connect)
}

fn dedicated_ipv4_egress_addresses(
    addresses: Vec<SocketAddr>,
    denied_ips: &HashSet<IpAddr>,
) -> Vec<SocketAddr> {
    let mut selected = Vec::new();
    for address in addresses {
        if !address.is_ipv4()
            || !is_public_destination_socket(address)
            || denied_ips.contains(&address.ip())
            || selected.contains(&address)
        {
            continue;
        }
        selected.push(address);
        if selected.len() >= MAX_RESOLVED_ADDRESSES {
            break;
        }
    }
    selected
}

async fn connect_from_gateway_ipv4(
    source_ip: Ipv4Addr,
    destination: SocketAddr,
) -> io::Result<TcpStream> {
    if !destination.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv6 egress requires a separately configured dedicated source",
        ));
    }
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::V4(SocketAddrV4::new(source_ip, 0)))?;
    socket.connect(destination).await
}

fn is_public_destination_socket(address: SocketAddr) -> bool {
    match address {
        SocketAddr::V4(address) => is_public_destination_ipv4(*address.ip()),
        SocketAddr::V6(address) => {
            address.scope_id() == 0 && is_public_destination_ipv6(*address.ip())
        }
    }
}

fn is_public_destination_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_destination_ipv4(address),
        IpAddr::V6(address) => is_public_destination_ipv6(address),
    }
}

fn is_public_destination_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    if a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
    {
        return false;
    }
    if (a, b, c) == (192, 0, 0)
        || (a, b) == (192, 88)
        || (a, b, c) == (192, 0, 2)
        || (a, b, c) == (198, 51, 100)
        || (a, b, c) == (203, 0, 113)
    {
        return false;
    }
    true
}

fn is_public_destination_ipv6(address: Ipv6Addr) -> bool {
    let bytes = address.octets();
    // Only global-unicast 2000::/3 is accepted, with special/documentation
    // ranges removed. This rejects ULA, link-local, multicast, unspecified,
    // IPv4-mapped, NAT64, discard-only and other reserved blocks.
    if bytes[0] & 0xe0 != 0x20 {
        return false;
    }
    if ipv6_has_prefix(bytes, [0x20, 0x01, 0x00, 0x00], 32) // Teredo
        || ipv6_has_prefix(bytes, [0x20, 0x01, 0x00, 0x02], 48) // benchmarking
        || ipv6_has_prefix(bytes, [0x20, 0x01, 0x00, 0x10], 28) // ORCHID
        || ipv6_has_prefix(bytes, [0x20, 0x01, 0x00, 0x20], 28) // ORCHIDv2
        || ipv6_has_prefix(bytes, [0x20, 0x01, 0x0d, 0xb8], 32) // documentation
        || ipv6_has_prefix(bytes, [0x20, 0x02, 0x00, 0x00], 16) // 6to4
        || ipv6_has_prefix(bytes, [0x3f, 0xff, 0x00, 0x00], 20)
    // documentation
    {
        return false;
    }
    true
}

fn ipv6_has_prefix(address: [u8; 16], prefix: [u8; 4], bits: u8) -> bool {
    let full_bytes = usize::from(bits / 8);
    let remaining_bits = bits % 8;
    for (index, byte) in address.iter().enumerate().take(full_bytes) {
        if *byte != prefix.get(index).copied().unwrap_or_default() {
            return false;
        }
    }
    if remaining_bits == 0 {
        return true;
    }
    let mask = 0xff << (8 - remaining_bits);
    address[full_bytes] & mask == prefix.get(full_bytes).copied().unwrap_or_default() & mask
}

#[derive(Default)]
struct QuotaCounts {
    by_sub: HashMap<String, usize>,
    by_jti: HashMap<String, usize>,
}

#[derive(Default)]
struct QuotaState {
    counts: Mutex<QuotaCounts>,
}

impl QuotaState {
    fn acquire(
        self: &Arc<Self>,
        sub: &str,
        jti: &str,
        max_per_sub: usize,
        max_per_jti: usize,
    ) -> Option<QuotaGuard> {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if counts.by_sub.get(sub).copied().unwrap_or_default() >= max_per_sub
            || counts.by_jti.get(jti).copied().unwrap_or_default() >= max_per_jti
        {
            return None;
        }
        *counts.by_sub.entry(sub.to_string()).or_default() += 1;
        *counts.by_jti.entry(jti.to_string()).or_default() += 1;
        Some(QuotaGuard {
            state: self.clone(),
            sub: sub.to_string(),
            jti: jti.to_string(),
        })
    }
}

struct QuotaGuard {
    state: Arc<QuotaState>,
    sub: String,
    jti: String,
}

impl Drop for QuotaGuard {
    fn drop(&mut self) {
        let mut counts = self
            .state
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        decrement_count(&mut counts.by_sub, &self.sub);
        decrement_count(&mut counts.by_jti, &self.jti);
    }
}

fn decrement_count(counts: &mut HashMap<String, usize>, key: &str) {
    if let Some(count) = counts.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(key);
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Metrics {
    enabled: AtomicBool,
    ready: AtomicBool,
    draining: AtomicBool,
    active_connections: AtomicU64,
    accepted_connections: AtomicU64,
    tls_failures: AtomicU64,
    parse_failures: AtomicU64,
    auth_failures: AtomicU64,
    policy_denied: AtomicU64,
    dns_failures: AtomicU64,
    connect_failures: AtomicU64,
    concurrency_rejected: AtomicU64,
    tunnels_established: AtomicU64,
    tunnels_completed: AtomicU64,
    active_tunnels: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    idle_timeouts: AtomicU64,
    byte_limit_exceeded: AtomicU64,
    token_expirations: AtomicU64,
    tunnel_errors: AtomicU64,
}

#[derive(Debug, Serialize)]
pub(crate) struct MetricsSnapshot {
    protocol: &'static str,
    enabled: bool,
    ready: bool,
    draining: bool,
    active_connections: u64,
    accepted_connections: u64,
    tls_failures: u64,
    parse_failures: u64,
    auth_failures: u64,
    policy_denied: u64,
    dns_failures: u64,
    connect_failures: u64,
    concurrency_rejected: u64,
    tunnels_established: u64,
    tunnels_completed: u64,
    active_tunnels: u64,
    bytes_up: u64,
    bytes_down: u64,
    idle_timeouts: u64,
    byte_limit_exceeded: u64,
    token_expirations: u64,
    tunnel_errors: u64,
}

impl Metrics {
    pub(crate) fn required_ready(&self) -> bool {
        !self.enabled.load(Ordering::Relaxed)
            || (self.ready.load(Ordering::Relaxed) && !self.draining.load(Ordering::Relaxed))
    }

    fn is_drained(&self) -> bool {
        self.active_connections.load(Ordering::Relaxed) == 0
    }

    pub(crate) fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            protocol: PROTOCOL_VERSION,
            enabled: self.enabled.load(Ordering::Relaxed),
            ready: self.ready.load(Ordering::Relaxed),
            draining: self.draining.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            tls_failures: self.tls_failures.load(Ordering::Relaxed),
            parse_failures: self.parse_failures.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            policy_denied: self.policy_denied.load(Ordering::Relaxed),
            dns_failures: self.dns_failures.load(Ordering::Relaxed),
            connect_failures: self.connect_failures.load(Ordering::Relaxed),
            concurrency_rejected: self.concurrency_rejected.load(Ordering::Relaxed),
            tunnels_established: self.tunnels_established.load(Ordering::Relaxed),
            tunnels_completed: self.tunnels_completed.load(Ordering::Relaxed),
            active_tunnels: self.active_tunnels.load(Ordering::Relaxed),
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            idle_timeouts: self.idle_timeouts.load(Ordering::Relaxed),
            byte_limit_exceeded: self.byte_limit_exceeded.load(Ordering::Relaxed),
            token_expirations: self.token_expirations.load(Ordering::Relaxed),
            tunnel_errors: self.tunnel_errors.load(Ordering::Relaxed),
        }
    }
}

struct ActiveConnectionGuard {
    metrics: Arc<Metrics>,
}

impl ActiveConnectionGuard {
    fn new(metrics: Arc<Metrics>) -> Self {
        metrics.active_connections.fetch_add(1, Ordering::Relaxed);
        Self { metrics }
    }
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.metrics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

struct ActiveTunnelGuard<'a> {
    metrics: &'a Metrics,
}

impl<'a> ActiveTunnelGuard<'a> {
    fn new(metrics: &'a Metrics) -> Self {
        metrics.active_tunnels.fetch_add(1, Ordering::Relaxed);
        Self { metrics }
    }
}

impl Drop for ActiveTunnelGuard<'_> {
    fn drop(&mut self) {
        self.metrics.active_tunnels.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PumpOutcome {
    Completed,
    IdleTimeout,
    ByteLimit,
    TokenExpired,
    IoError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectionOutcome {
    Eof,
    IdleTimeout,
    ByteLimit,
    TokenExpired,
    IoError,
    Aborted,
}

#[derive(Debug, Clone, Copy)]
enum TrafficDirection {
    Up,
    Down,
}

struct PumpState<'a> {
    started: Instant,
    last_activity_ms: AtomicU64,
    total_bytes: AtomicU64,
    abort: AtomicBool,
    max_bytes: u64,
    idle_timeout: Duration,
    token_deadline: Instant,
    metrics: &'a Metrics,
}

impl PumpState<'_> {
    fn touch(&self) {
        self.last_activity_ms
            .store(self.elapsed_ms(), Ordering::Relaxed);
    }

    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    fn is_idle(&self) -> bool {
        let elapsed = self.elapsed_ms();
        let last = self.last_activity_ms.load(Ordering::Relaxed);
        elapsed.saturating_sub(last) >= self.idle_timeout.as_millis() as u64
    }

    fn add_bytes(&self, bytes: usize) -> bool {
        let bytes = bytes as u64;
        self.total_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current
                    .checked_add(bytes)
                    .filter(|next| *next <= self.max_bytes)
            })
            .is_ok()
    }

    fn remaining_token_time(&self) -> Option<Duration> {
        let remaining = self
            .token_deadline
            .saturating_duration_since(Instant::now());
        (!remaining.is_zero()).then_some(remaining)
    }

    fn record_bytes(&self, direction: TrafficDirection, bytes: usize) {
        let target = match direction {
            TrafficDirection::Up => &self.metrics.bytes_up,
            TrafficDirection::Down => &self.metrics.bytes_down,
        };
        target.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

async fn pump_tunnel<C>(
    client: C,
    upstream: TcpStream,
    initial_upstream_data: Vec<u8>,
    token_exp_unix: i64,
    config: &Config,
    metrics: &Metrics,
) -> PumpOutcome
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let Some(tunnel_ttl) = token_ttl(token_exp_unix, unix_time_secs()) else {
        return PumpOutcome::TokenExpired;
    };
    let state = Arc::new(PumpState {
        started: Instant::now(),
        last_activity_ms: AtomicU64::new(0),
        total_bytes: AtomicU64::new(0),
        abort: AtomicBool::new(false),
        max_bytes: config.max_tunnel_bytes,
        idle_timeout: config.idle_timeout,
        token_deadline: Instant::now() + tunnel_ttl,
        metrics,
    });

    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, mut upstream_write) = upstream.into_split();
    if !initial_upstream_data.is_empty() {
        if !state.add_bytes(initial_upstream_data.len()) {
            return PumpOutcome::ByteLimit;
        }
        let write_timeout = config.idle_timeout.min(tunnel_ttl);
        match timeout(
            write_timeout,
            upstream_write.write_all(&initial_upstream_data),
        )
        .await
        {
            Ok(Ok(())) => {
                state.record_bytes(TrafficDirection::Up, initial_upstream_data.len());
                state.touch();
            }
            Ok(Err(_)) => return PumpOutcome::IoError,
            Err(_) => return PumpOutcome::IdleTimeout,
        }
    }

    let up = copy_direction(
        client_read,
        upstream_write,
        state.clone(),
        TrafficDirection::Up,
    );
    let down = copy_direction(
        upstream_read,
        client_write,
        state.clone(),
        TrafficDirection::Down,
    );
    let (up, down) = tokio::join!(up, down);
    combine_direction_outcomes(up, down)
}

fn token_ttl(exp_unix: i64, now_unix: i64) -> Option<Duration> {
    let seconds = exp_unix.checked_sub(now_unix)?;
    (seconds > 0).then(|| Duration::from_secs(seconds as u64))
}

async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    state: Arc<PumpState<'_>>,
    direction: TrafficDirection,
) -> DirectionOutcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        if state.abort.load(Ordering::Relaxed) {
            return DirectionOutcome::Aborted;
        }
        let Some(token_remaining) = state.remaining_token_time() else {
            state.abort.store(true, Ordering::Relaxed);
            return DirectionOutcome::TokenExpired;
        };
        let poll_for = Duration::from_millis(500)
            .min(state.idle_timeout)
            .min(token_remaining);
        let count = match timeout(poll_for, reader.read(&mut buffer)).await {
            Ok(Ok(0)) => {
                let Some(token_remaining) = state.remaining_token_time() else {
                    state.abort.store(true, Ordering::Relaxed);
                    return DirectionOutcome::TokenExpired;
                };
                // A WebKit tab switch normally closes the client half of a
                // tunnel while the remote side may keep its TLS/socket open for
                // a long time. If we only return EOF from this direction, the
                // sibling copy task can sit in read() until the full idle
                // timeout, retaining the per-user/per-token quota slot. Signal
                // abort first and bound FIN propagation tightly so bursty
                // app-switches free admission capacity immediately.
                state.abort.store(true, Ordering::Relaxed);
                let shutdown_for = Duration::from_millis(HALF_CLOSE_SHUTDOWN_TIMEOUT_MS)
                    .min(state.idle_timeout)
                    .min(token_remaining);
                return match timeout(shutdown_for, writer.shutdown()).await {
                    Ok(Ok(())) => DirectionOutcome::Eof,
                    Ok(Err(_)) => {
                        state.abort.store(true, Ordering::Relaxed);
                        DirectionOutcome::IoError
                    }
                    Err(_) if state.remaining_token_time().is_none() => {
                        state.abort.store(true, Ordering::Relaxed);
                        DirectionOutcome::TokenExpired
                    }
                    Err(_) => {
                        state.abort.store(true, Ordering::Relaxed);
                        DirectionOutcome::IdleTimeout
                    }
                };
            }
            Ok(Ok(count)) => count,
            Ok(Err(_)) => {
                state.abort.store(true, Ordering::Relaxed);
                return DirectionOutcome::IoError;
            }
            Err(_) if state.remaining_token_time().is_none() => {
                state.abort.store(true, Ordering::Relaxed);
                return DirectionOutcome::TokenExpired;
            }
            Err(_) if state.is_idle() => {
                state.abort.store(true, Ordering::Relaxed);
                return DirectionOutcome::IdleTimeout;
            }
            Err(_) => continue,
        };

        state.touch();
        if !state.add_bytes(count) {
            state.abort.store(true, Ordering::Relaxed);
            return DirectionOutcome::ByteLimit;
        }
        let Some(token_remaining) = state.remaining_token_time() else {
            state.abort.store(true, Ordering::Relaxed);
            return DirectionOutcome::TokenExpired;
        };
        let write_for = state.idle_timeout.min(token_remaining);
        match timeout(write_for, writer.write_all(&buffer[..count])).await {
            Ok(Ok(())) => {
                state.record_bytes(direction, count);
                state.touch();
            }
            Ok(Err(_)) => {
                state.abort.store(true, Ordering::Relaxed);
                return DirectionOutcome::IoError;
            }
            Err(_) if state.remaining_token_time().is_none() => {
                state.abort.store(true, Ordering::Relaxed);
                return DirectionOutcome::TokenExpired;
            }
            Err(_) => {
                state.abort.store(true, Ordering::Relaxed);
                return DirectionOutcome::IdleTimeout;
            }
        }
    }
}

fn combine_direction_outcomes(first: DirectionOutcome, second: DirectionOutcome) -> PumpOutcome {
    let outcomes = [first, second];
    if outcomes.contains(&DirectionOutcome::ByteLimit) {
        PumpOutcome::ByteLimit
    } else if outcomes.contains(&DirectionOutcome::TokenExpired) {
        PumpOutcome::TokenExpired
    } else if outcomes.contains(&DirectionOutcome::IdleTimeout) {
        PumpOutcome::IdleTimeout
    } else if outcomes.contains(&DirectionOutcome::IoError) {
        PumpOutcome::IoError
    } else {
        PumpOutcome::Completed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    const FIXTURE_SECRET: &str = "0123456789abcdef0123456789abcdef";
    const FIXTURE_PAYLOAD: &str = "eyJ2IjoxLCJhdWQiOiJnYXRld2F5LW5sLWRldi0xIiwic3ViIjoiODVzUTE2SzkwRnhvVHJLdmhnRGdQdyIsImp0aSI6IkFBRUNBd1FGQmdjSUNRb0xEQTBPRHciLCJpYXQiOjE3ODM5NjU2MDAsImV4cCI6MTc4Mzk2NjIwMCwicmVnaW9uIjoibmwiLCJhcHAiOiJ0ZWxlZ3JhbSIsImRzdCI6WyJ3ZWIudGVsZWdyYW0ub3JnIiwidGVsZWdyYW0ub3JnIiwiKi50ZWxlZ3JhbS5vcmciLCJ0Lm1lIiwiKi50Lm1lIiwidGVsZWdyYW0ubWUiLCIqLnRlbGVncmFtLm1lIl19";
    const FIXTURE_TOKEN: &str = "cwg1.eyJ2IjoxLCJhdWQiOiJnYXRld2F5LW5sLWRldi0xIiwic3ViIjoiODVzUTE2SzkwRnhvVHJLdmhnRGdQdyIsImp0aSI6IkFBRUNBd1FGQmdjSUNRb0xEQTBPRHciLCJpYXQiOjE3ODM5NjU2MDAsImV4cCI6MTc4Mzk2NjIwMCwicmVnaW9uIjoibmwiLCJhcHAiOiJ0ZWxlZ3JhbSIsImRzdCI6WyJ3ZWIudGVsZWdyYW0ub3JnIiwidGVsZWdyYW0ub3JnIiwiKi50ZWxlZ3JhbS5vcmciLCJ0Lm1lIiwiKi50Lm1lIiwidGVsZWdyYW0ubWUiLCIqLnRlbGVncmFtLm1lIl19.glIxJzMhZz8KKL_eqws-6VZSYU8OTpoAYJHdJH_N8gE";

    fn test_config() -> Config {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["gateway.example.test".to_string()]).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        Config {
            bind: "93.184.216.34:443".parse().unwrap(),
            listen_bind: "93.184.216.34:443".parse().unwrap(),
            metrics_bind: "127.0.0.1:9800".parse().unwrap(),
            gateway_id: "gateway-nl-dev-1".to_string(),
            region: "nl".to_string(),
            diagnostics_host: "canary.example.net".to_string(),
            denied_host_suffixes: vec![
                "api.example.com".to_string(),
                "gateway.example.com".to_string(),
            ],
            denied_ips: HashSet::from(["93.184.216.34".parse().unwrap()]),
            allowed_ports: HashSet::from([443]),
            hmac_secret: Arc::from(FIXTURE_SECRET.as_bytes()),
            previous_hmac_secret: None,
            tls_config: Arc::new(build_tls_config(vec![cert.der().clone()], key).unwrap()),
            tls_handshake_timeout: Duration::from_secs(5),
            header_timeout: Duration::from_secs(3),
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
            max_header_bytes: 16 * 1024,
            max_tunnel_bytes: 1024 * 1024,
            max_concurrent: 8,
            max_concurrent_per_sub: 2,
            max_concurrent_per_jti: 1,
            clock_skew_secs: 15,
            max_token_lifetime_secs: 900,
            graceful_drain_timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn fronted_listener_is_loopback_and_unprivileged() {
        assert_eq!(
            parse_gateway_listen_bind("127.0.0.1:9443").unwrap(),
            "127.0.0.1:9443".parse::<SocketAddrV4>().unwrap()
        );
        for rejected in ["0.0.0.0:9443", "93.184.216.34:9443", "127.0.0.1:443"] {
            assert!(
                parse_gateway_listen_bind(rejected).is_err(),
                "accepted {rejected}"
            );
        }
    }

    fn proxy_request(token: &str) -> Vec<u8> {
        let credentials = STANDARD.encode(format!("cornel:{token}"));
        format!(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {credentials}\r\nProxy-Connection: keep-alive\r\n\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn deterministic_hmac_fixture_matches_cross_language_contract() {
        let config = test_config();
        let payload = URL_SAFE_NO_PAD.decode(FIXTURE_PAYLOAD).unwrap();
        assert_eq!(
            std::str::from_utf8(&payload).unwrap(),
            r#"{"v":1,"aud":"gateway-nl-dev-1","sub":"85sQ16K90FxoTrKvhgDgPw","jti":"AAECAwQFBgcICQoLDA0ODw","iat":1783965600,"exp":1783966200,"region":"nl","app":"telegram","dst":["web.telegram.org","telegram.org","*.telegram.org","t.me","*.t.me","telegram.me","*.telegram.me"]}"#
        );
        let claims = verify_token(FIXTURE_TOKEN, &config, 1_783_965_601).unwrap();
        assert_eq!(claims.v, 1);
        assert_eq!(claims.aud, "gateway-nl-dev-1");
        assert_eq!(claims.region, "nl");
        assert_eq!(claims.app, "telegram");
        assert_eq!(claims.iat, 1_783_965_600);
        assert_eq!(claims.exp, 1_783_966_200);
        assert!(destination_scope_matches("web.telegram.org", &claims.dst));
    }

    #[test]
    fn token_rejects_tampering_wrong_audience_and_expiry() {
        let config = test_config();
        let mut tampered = FIXTURE_TOKEN.as_bytes().to_vec();
        let payload_offset = TOKEN_PREFIX.len() + 1;
        tampered[payload_offset] = if tampered[payload_offset] == b'a' {
            b'b'
        } else {
            b'a'
        };
        assert!(matches!(
            verify_token(
                std::str::from_utf8(&tampered).unwrap(),
                &config,
                1_783_965_601
            ),
            Err(TokenError::Invalid)
        ));

        let mut wrong_audience = test_config();
        wrong_audience.gateway_id = "another-gateway".to_string();
        assert!(matches!(
            verify_token(FIXTURE_TOKEN, &wrong_audience, 1_783_965_601),
            Err(TokenError::Invalid)
        ));
        assert!(matches!(
            verify_token(FIXTURE_TOKEN, &config, 1_783_966_200),
            Err(TokenError::Expired)
        ));

        let mut during_rotation = test_config();
        during_rotation.hmac_secret = Arc::from(b"new-secret-0123456789abcdef012345".as_slice());
        during_rotation.previous_hmac_secret = Some(Arc::from(FIXTURE_SECRET.as_bytes()));
        assert!(verify_token(FIXTURE_TOKEN, &during_rotation, 1_783_965_601).is_ok());
    }

    #[test]
    fn connect_parser_accepts_only_strict_authenticated_https_authority() {
        let allowed_ports = HashSet::from([443]);
        let mut bytes = proxy_request(FIXTURE_TOKEN);
        bytes.extend_from_slice(b"early-tunnel-data");
        let request = parse_connect_request(&bytes, &allowed_ports).unwrap();
        assert_eq!(request.host, "example.com");
        assert_eq!(request.port, 443);
        assert_eq!(request.token, FIXTURE_TOKEN);
        assert_eq!(request.initial_tunnel_data, b"early-tunnel-data");

        let missing_auth = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        assert!(matches!(
            parse_connect_request(missing_auth, &allowed_ports),
            Err(RequestError::Authentication)
        ));
        let wrong_port = String::from_utf8(proxy_request(FIXTURE_TOKEN))
            .unwrap()
            .replace(":443", ":80");
        assert!(matches!(
            parse_connect_request(wrong_port.as_bytes(), &allowed_ports),
            Err(RequestError::Policy)
        ));
        let ip_literal = String::from_utf8(proxy_request(FIXTURE_TOKEN))
            .unwrap()
            .replace("example.com", "93.184.216.34");
        assert!(matches!(
            parse_connect_request(ip_literal.as_bytes(), &allowed_ports),
            Err(RequestError::Policy)
        ));
    }

    #[test]
    fn signed_destination_scope_is_canonical_bounded_and_exact() {
        let scope = vec!["web.telegram.org".to_string(), "*.telegram.org".to_string()];
        assert!(validate_destination_scope(&scope).is_ok());
        assert!(destination_scope_matches("web.telegram.org", &scope));
        assert!(destination_scope_matches("telegram.org", &scope));
        assert!(destination_scope_matches("cdn.telegram.org", &scope));
        assert!(!destination_scope_matches("nottelegram.org", &scope));
        assert!(!destination_scope_matches(
            "telegram.org.example.com",
            &scope
        ));

        assert!(validate_destination_scope(&[]).is_err());
        assert!(validate_destination_scope(&["Telegram.org".to_string()]).is_err());
        assert!(validate_destination_scope(&["telegram.org.".to_string()]).is_err());
        assert!(validate_destination_scope(&["*telegram.org".to_string()]).is_err());
        assert!(validate_destination_scope(&[
            "telegram.org".to_string(),
            "telegram.org".to_string(),
        ])
        .is_err());
        assert!(validate_destination_scope(
            &(0..=MAX_DESTINATION_PATTERNS)
                .map(|index| format!("host-{index}.example.com"))
                .collect::<Vec<_>>()
        )
        .is_err());
    }

    #[test]
    fn hostname_and_ip_policies_fail_closed() {
        let suffixes = parse_host_suffixes("api.example.com, gateway.example.com").unwrap();
        assert!(is_denied_host(
            "api.example.com",
            "canary.example.net",
            &suffixes
        ));
        assert!(is_denied_host(
            "internal.api.example.com",
            "canary.example.net",
            &suffixes
        ));
        assert!(!is_denied_host(
            "canary.example.net",
            "canary.example.net",
            &suffixes
        ));
        assert!(!is_denied_host(
            "notapi.example.com",
            "canary.example.net",
            &suffixes
        ));

        for denied in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff00::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
        ] {
            assert!(
                !is_public_destination_ip(denied.parse().unwrap()),
                "{denied}"
            );
        }
        for allowed in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(
                is_public_destination_ip(allowed.parse().unwrap()),
                "{allowed}"
            );
        }
    }

    #[test]
    fn quota_and_byte_limit_guards_release_exactly() {
        let quotas = Arc::new(QuotaState::default());
        let first = quotas.acquire("subject", "jti", 2, 1).unwrap();
        assert!(quotas.acquire("subject", "jti", 2, 1).is_none());
        drop(first);
        assert!(quotas.acquire("subject", "jti", 2, 1).is_some());

        let metrics = Metrics::default();
        let state = PumpState {
            started: Instant::now(),
            last_activity_ms: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            abort: AtomicBool::new(false),
            max_bytes: 10,
            idle_timeout: Duration::from_secs(30),
            token_deadline: Instant::now() + Duration::from_secs(60),
            metrics: &metrics,
        };
        assert!(state.add_bytes(6));
        assert!(state.add_bytes(4));
        assert!(!state.add_bytes(1));
        assert_eq!(state.total_bytes.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn config_parsers_reject_open_or_ambiguous_policy() {
        assert!(validate_hmac_secret(b"too-short").is_err());
        assert!(parse_allowed_ports("").is_err());
        assert!(parse_allowed_ports("0").is_err());
        assert_eq!(parse_allowed_ports("443").unwrap(), HashSet::from([443]));
        assert!(parse_host_suffixes("").is_err());
        assert!(parse_denied_ips("").is_err());
        assert!(parse_denied_ips("127.0.0.1").is_err());
        assert!(parse_gateway_bind("0.0.0.0:443").is_err());
        assert!(parse_gateway_bind("127.0.0.1:443").is_err());
        assert!(parse_gateway_bind("gateway.example.com:443").is_err());
        assert!(parse_gateway_bind("1.1.1.1:0").is_err());
        assert_eq!(
            parse_gateway_bind("1.1.1.1:443").unwrap(),
            "1.1.1.1:443".parse().unwrap()
        );
        // A gateway must be deployable off 443. Pinning the port here is what
        // forced a tunnel burst onto the same port number the platform's own
        // website and API answer on, and took them down with it.
        assert_eq!(
            parse_gateway_bind("1.1.1.1:8443").unwrap(),
            "1.1.1.1:8443".parse().unwrap()
        );
        assert_eq!(
            parse_metrics_bind("127.0.0.1:9800").unwrap(),
            "127.0.0.1:9800".parse().unwrap()
        );
        assert_eq!(
            parse_metrics_bind("[::1]:9800").unwrap(),
            "[::1]:9800".parse().unwrap()
        );
        assert!(parse_metrics_bind("0.0.0.0:9800").is_err());
        assert!(parse_metrics_bind("127.0.0.1:0").is_err());
    }

    #[test]
    fn direction_outcomes_prefer_security_limits() {
        assert_eq!(
            combine_direction_outcomes(DirectionOutcome::ByteLimit, DirectionOutcome::Aborted),
            PumpOutcome::ByteLimit
        );
        assert_eq!(
            combine_direction_outcomes(DirectionOutcome::TokenExpired, DirectionOutcome::Aborted),
            PumpOutcome::TokenExpired
        );
        assert_eq!(
            combine_direction_outcomes(DirectionOutcome::Eof, DirectionOutcome::Eof),
            PumpOutcome::Completed
        );
        assert_eq!(token_ttl(101, 100), Some(Duration::from_secs(1)));
        assert_eq!(token_ttl(100, 100), None);
        assert_eq!(token_ttl(99, 100), None);

        let metrics = Metrics::default();
        assert!(metrics.required_ready());
        metrics.enabled.store(true, Ordering::Relaxed);
        assert!(!metrics.required_ready());
        metrics.ready.store(true, Ordering::Relaxed);
        assert!(metrics.required_ready());
        metrics.draining.store(true, Ordering::Relaxed);
        assert!(!metrics.required_ready());
        assert!(metrics.is_drained());
        let active = ActiveConnectionGuard::new(Arc::new(metrics));
        assert!(!active.metrics.is_drained());
        drop(active);
    }

    #[test]
    fn local_metrics_routes_and_prometheus_output_are_fail_closed() {
        assert_eq!(
            local_metrics_request_kind("GET /metrics HTTP/1.1"),
            LocalMetricsRequestKind::Metrics
        );
        assert_eq!(
            local_metrics_request_kind("GET /healthz HTTP/1.1"),
            LocalMetricsRequestKind::Health
        );
        assert_eq!(
            local_metrics_request_kind("GET /readyz HTTP/1.1"),
            LocalMetricsRequestKind::Ready
        );
        assert_eq!(
            local_metrics_request_kind("GET /secret HTTP/1.1"),
            LocalMetricsRequestKind::NotFound
        );
        assert_eq!(
            local_metrics_request_kind("POST /metrics HTTP/1.1"),
            LocalMetricsRequestKind::BadRequest
        );

        let metrics = Metrics::default();
        metrics.ready.store(true, Ordering::Relaxed);
        metrics.accepted_connections.store(7, Ordering::Relaxed);
        let rendered = render_prometheus_metrics(&metrics);
        assert!(rendered.contains("cornel_web_gateway_ready 1\n"));
        assert!(rendered.contains("cornel_web_gateway_accepted_connections_total 7\n"));
        assert!(!rendered.contains('{'));
    }

    #[test]
    fn dedicated_ipv4_egress_never_uses_shared_ipv6_route() {
        let denied = HashSet::new();
        let v6_first: Vec<SocketAddr> = vec![
            "[2606:4700:4700::1111]:443".parse().unwrap(),
            "[2001:4860:4860::8888]:443".parse().unwrap(),
            "1.1.1.1:443".parse().unwrap(),
            "8.8.8.8:443".parse().unwrap(),
        ];
        assert_eq!(
            dedicated_ipv4_egress_addresses(v6_first, &denied),
            vec![
                "1.1.1.1:443".parse().unwrap(),
                "8.8.8.8:443".parse().unwrap(),
            ]
        );
        assert!(dedicated_ipv4_egress_addresses(
            vec!["[2606:4700:4700::1111]:443".parse().unwrap(),],
            &denied,
        )
        .is_empty());
    }

    #[test]
    fn dedicated_ipv4_egress_filters_cdns_without_rejecting_entire_answer() {
        let denied = HashSet::from([IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]);
        let mut addresses: Vec<SocketAddr> = vec![
            "10.0.0.1:443".parse().unwrap(),
            "203.0.113.7:443".parse().unwrap(),
            "[2606:4700:4700::1111]:443".parse().unwrap(),
        ];
        for index in 1..=24 {
            addresses.push(format!("8.8.4.{index}:443").parse().unwrap());
        }

        let selected = dedicated_ipv4_egress_addresses(addresses, &denied);
        assert_eq!(selected.len(), MAX_RESOLVED_ADDRESSES);
        assert_eq!(selected[0], "8.8.4.1:443".parse().unwrap());
        assert!(!selected.contains(&"10.0.0.1:443".parse().unwrap()));
        assert!(!selected.contains(&"203.0.113.7:443".parse().unwrap()));
    }

    struct StalledShutdownWriter;

    impl AsyncWrite for StalledShutdownWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn stalled_shutdown_is_bounded_and_releases_connection_quotas() {
        let metrics = Metrics::default();
        let state = Arc::new(PumpState {
            started: Instant::now(),
            last_activity_ms: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            abort: AtomicBool::new(false),
            max_bytes: 1024,
            idle_timeout: Duration::from_millis(25),
            token_deadline: Instant::now() + Duration::from_secs(1),
            metrics: &metrics,
        });
        let concurrency = Arc::new(Semaphore::new(1));
        let quotas = Arc::new(QuotaState::default());

        {
            let _permit = concurrency.clone().acquire_owned().await.unwrap();
            let _quota = quotas.acquire("subject", "token", 1, 1).unwrap();
            let outcome = timeout(
                Duration::from_secs(1),
                copy_direction(
                    tokio::io::empty(),
                    StalledShutdownWriter,
                    state,
                    TrafficDirection::Down,
                ),
            )
            .await
            .expect("stalled shutdown must not retain the connection task");
            assert_eq!(outcome, DirectionOutcome::IdleTimeout);
        }

        assert_eq!(concurrency.available_permits(), 1);
        assert!(quotas.acquire("subject", "token", 1, 1).is_some());
    }

    #[tokio::test]
    async fn client_eof_aborts_peer_direction_without_waiting_for_idle_timeout() {
        let metrics = Metrics::default();
        let state = Arc::new(PumpState {
            started: Instant::now(),
            last_activity_ms: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            abort: AtomicBool::new(false),
            max_bytes: 1024,
            idle_timeout: Duration::from_secs(30),
            token_deadline: Instant::now() + Duration::from_secs(60),
            metrics: &metrics,
        });

        let outcome = timeout(
            Duration::from_secs(1),
            copy_direction(
                tokio::io::empty(),
                tokio::io::sink(),
                state.clone(),
                TrafficDirection::Up,
            ),
        )
        .await
        .expect("client EOF must complete without waiting for idle timeout");

        assert_eq!(outcome, DirectionOutcome::Eof);
        assert!(state.abort.load(Ordering::Relaxed));
    }
}
