use std::env;
use std::io;
use std::sync::Arc;

use serde::Serialize;

mod gateway;

const CAPABILITIES: &[&str] = &[
    "dedicated-data-plane-v1",
    "kernel-egress-guard-v1",
    "graceful-drain-v1",
];

#[derive(Serialize)]
struct BuildInfo {
    name: &'static str,
    version: &'static str,
    build_version: &'static str,
    git_commit: &'static str,
    built_at_unix: &'static str,
    protocol: &'static str,
    capabilities: &'static [&'static str],
}

fn build_info() -> BuildInfo {
    BuildInfo {
        name: "tenzor-webapp-relay",
        version: env!("CARGO_PKG_VERSION"),
        build_version: option_env!("TENZOR_BUILD_VERSION").unwrap_or("dev"),
        git_commit: option_env!("TENZOR_GIT_COMMIT").unwrap_or("unknown"),
        built_at_unix: option_env!("TENZOR_BUILT_AT_UNIX").unwrap_or("unknown"),
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
