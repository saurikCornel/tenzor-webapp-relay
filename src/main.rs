use std::env;
use std::io;
use std::sync::Arc;

use serde::Serialize;
use sha2::{Digest, Sha256};

mod gateway;

const BUILD_SCHEMA: &str = "tenzor-module-build-v1";

const COMPONENTS: &[Option<&str>] = &[
    option_env!("TENZOR_COMPONENT_SERVER"),
    option_env!("TENZOR_COMPONENT_CORE"),
    option_env!("TENZOR_COMPONENT_GATE"),
    option_env!("TENZOR_COMPONENT_RELAY"),
    option_env!("TENZOR_COMPONENT_CLIENT"),
    option_env!("TENZOR_COMPONENT_SANITIZE"),
    option_env!("TENZOR_COMPONENT_WEBAPP_RELAY"),
    option_env!("TENZOR_COMPONENT_VK_TURN"),
    option_env!("TENZOR_COMPONENT_OPENWRT"),
    option_env!("TENZOR_COMPONENT_PARTNER"),
    option_env!("TENZOR_COMPONENT_WEB"),
];

const CAPABILITIES: &[&str] = &[
    "dedicated-data-plane-v1",
    "kernel-egress-guard-v1",
    "graceful-drain-v1",
];

#[derive(Serialize)]
struct DependencyLock {
    file: &'static str,
    sha256: String,
}

#[derive(Serialize)]
struct BuildInfo {
    schema: &'static str,
    module: &'static str,
    components: Vec<&'static str>,
    name: &'static str,
    version: &'static str,
    build_version: &'static str,
    git_commit: &'static str,
    built_at_unix: &'static str,
    dependency_lock: DependencyLock,
    protocol: &'static str,
    capabilities: &'static [&'static str],
}

fn build_metadata(value: Option<&'static str>, fallback: &'static str) -> &'static str {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
}

fn build_components() -> Vec<&'static str> {
    COMPONENTS
        .iter()
        .filter_map(|value| value.map(str::trim).filter(|value| !value.is_empty()))
        .collect()
}

// Only compile-time inputs belong here: this path must not read runtime
// configuration, credentials, files or open sockets.
fn build_info() -> BuildInfo {
    BuildInfo {
        schema: BUILD_SCHEMA,
        module: "tenzor-webapp-relay",
        components: build_components(),
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        build_version: build_metadata(option_env!("TENZOR_BUILD_VERSION"), "dev"),
        git_commit: build_metadata(option_env!("TENZOR_GIT_COMMIT"), "unknown"),
        built_at_unix: build_metadata(option_env!("TENZOR_BUILT_AT_UNIX"), "unknown"),
        dependency_lock: DependencyLock {
            file: "Cargo.lock",
            sha256: format!("{:x}", Sha256::digest(include_bytes!("../Cargo.lock"))),
        },
        protocol: gateway::PROTOCOL_VERSION,
        capabilities: CAPABILITIES,
    }
}

fn configured_gateway() -> io::Result<gateway::Config> {
    gateway::Config::from_env()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "TENZOR_WEBAPP_RELAY_* configuration is required",
            )
        })
}

fn print_help() {
    println!(
        "tenzor-webapp-relay\n\nUSAGE:\n    tenzor-webapp-relay [--check-config|--version-json|--help]"
    );
}

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let mode = args.next();
    if args.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at most one process-mode flag is accepted",
        ));
    }

    match mode.as_deref() {
        Some("--version-json") => {
            println!(
                "{}",
                serde_json::to_string_pretty(&build_info()).expect("build info is serializable")
            );
            Ok(())
        }
        Some("--check-config") => {
            let _ = configured_gateway()?;
            println!("{{\"ok\":true}}");
            Ok(())
        }
        Some("--help" | "-h") => {
            print_help();
            Ok(())
        }
        None => {
            gateway::run_dedicated(configured_gateway()?, Arc::new(gateway::Metrics::default()))
        }
        Some(flag) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown flag: {flag}"),
        )),
    }
}
