#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::enum_glob_use,
    clippy::module_name_repetitions,
    clippy::single_match_else,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unused_async,
    clippy::wildcard_imports
)]

#[macro_use]
mod macros;

mod agents;
mod bridges;
mod config;
mod crypto;
mod email_address;
mod error;
mod handlers;
mod metrics;
mod router;
mod utils;
mod validation;
mod web;
mod webfinger;

use crate::agents::{Expiring, ExportKeySet, ImportKeySet, KeySet};
use crate::config::{ConfigBuilder, ConfigRc};
use crate::utils::{pem, BoxError};
use crate::web::Service;
use futures_util::future;
use hyper::{server::Server, service::make_service_fn};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Write};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::SystemTime,
};

/// Defines the program's version, as set by Cargo at compile time.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Defines the program's usage string.
///
/// [Docopt](http://docopt.org) parses this and generates a custom argv parser.
const USAGE: &str = r#"
Portier Broker

Usage:
  portier-broker [CONFIG]
  portier-broker [CONFIG] --import-keys FILE [--dry-run]
  portier-broker [CONFIG] --export-keys FILE
  portier-broker --version
  portier-broker --help

Options:
  --version           Print version information and exit
  --help              Print this help message and exit

  --import-keys FILE  Import PEM private keys
  --dry-run           Parse PEM to be imported, but don't apply changes

  --export-keys FILE  Export currently active private keys as PEM
"#;

/// Holds parsed command line parameters.
#[derive(Deserialize)]
#[allow(non_snake_case)]
struct Args {
    arg_CONFIG: Option<PathBuf>,
    flag_import_keys: Option<PathBuf>,
    flag_export_keys: Option<PathBuf>,
    flag_dry_run: bool,
}

/// The `main()` method. Will loop forever to serve HTTP requests.
#[tokio::main]
async fn main() {
    crate::utils::logger::init();

    // We spawn a bunch of background tasks on the Tokio executor. If these panic, we want to exit
    // instead of continuing on without the task.
    let next_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        next_panic_hook(info);
        std::process::exit(1);
    }));

    let args: Args = docopt::Docopt::new(USAGE)
        .map(|docopt| docopt.version(Some(VERSION.to_owned())))
        .and_then(|docopt| docopt.deserialize())
        .unwrap_or_else(|e| e.exit());

    let mut builder = ConfigBuilder::new();
    if let Some(ref path) = args.arg_CONFIG {
        builder.update_from_file(path);
    }
    builder.update_from_common_env();
    builder.update_from_broker_env();

    if let Some(ref path) = args.flag_import_keys {
        import_keys(builder, path, args.flag_dry_run).await;
    } else if let Some(ref path) = args.flag_export_keys {
        export_keys(builder, path).await;
    } else {
        start_server(builder).await;
    }
}

async fn start_server(builder: ConfigBuilder) {
    let app = ConfigRc::new(
        builder
            .done()
            .await
            .unwrap_or_else(|err| panic!("failed to build configuration: {err}")),
    );

    // TODO: Add unix socket support.
    let builder = match listenfd::ListenFd::from_env().take_tcp_listener(0) {
        Ok(Some(tcp_listener)) => {
            let builder = Server::from_tcp(tcp_listener).expect("Socket activation failed");
            log::info!("Listening on the socket received from the service manager");
            builder
        }
        Ok(None) => {
            let ip_addr = app
                .listen_ip
                .parse()
                .expect("Unable to parse listen address");
            let addr = SocketAddr::new(ip_addr, app.listen_port);
            let builder = Server::bind(&addr);
            log::info!("Listening on {}", addr);
            builder
        }
        Err(err) => {
            panic!("Socket activation failed: {err}");
        }
    };

    #[cfg(unix)]
    sd_notify::notify(true, &[sd_notify::NotifyState::Ready])
        .expect("Failed to signal ready to the service manager");

    let make_service = make_service_fn(|stream| {
        metrics::HTTP_CONNECTIONS.inc();
        let app = ConfigRc::clone(&app);
        future::ok::<_, BoxError>(Service::new(app, stream))
    });
    let server = builder.serve(make_service);

    let (exit_tx, mut exit_rx) = tokio::sync::mpsc::channel(1);
    ctrlc::set_handler(move || {
        exit_tx
            .blocking_send(())
            .expect("Could not send the exit signal");
    })
    .expect("Could not install the exit signal handler");
    let server = server.with_graceful_shutdown(async move {
        exit_rx
            .recv()
            .await
            .expect("Could not wait for the exit signal");
        log::info!("Shutting down");
    });

    server.await.expect("Server error");
    log::info!("Shutdown complete");
}

async fn import_keys(builder: ConfigBuilder, path: &Path, dry_run: bool) {
    if builder.is_keyed_manually() {
        eprintln!("Importing keys, but configuration uses manual keying.");
        eprintln!("Make sure to remove 'keyfiles' and 'keytext' options");
        eprintln!("afterwards, to switch to automatic key rotation.");
    }

    let entries = if path == Path::new("-") {
        pem::parse_key_pairs(BufReader::new(std::io::stdin())).expect("Could not read from stdin")
    } else {
        let file = File::open(path).expect("Could not open file");
        pem::parse_key_pairs(BufReader::new(file)).expect("Could not read from file")
    };

    let mut key_sets = HashMap::new();
    let mut fail = false;
    for (idx, result) in entries.into_iter().enumerate() {
        let idx = idx + 1;
        let entry = match result {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!("#{idx}: parse error, {err}");
                fail = true;
                continue;
            }
        };

        let alg = entry.key_pair.signing_alg();
        if !builder.signing_algs.contains(&alg) {
            eprintln!("#{idx}: ignored, disabled signing algorithm");
            continue;
        }

        let key_set = key_sets.entry(alg).or_insert(KeySet {
            signing_alg: alg,
            current: None,
            next: None,
            previous: None,
        });

        let fp = entry.raw.fingerprint();
        let (purpose, lifespan) = if key_set.current.is_none() {
            let lifespan = builder.keys_ttl;
            key_set.current = Some(Expiring {
                value: entry.raw.encode(),
                expires: SystemTime::now() + lifespan,
            });
            ("current", Some(lifespan))
        } else if key_set.next.is_none() {
            let lifespan = builder.keys_ttl * 2;
            key_set.next = Some(Expiring {
                value: entry.raw.encode(),
                expires: SystemTime::now() + lifespan,
            });
            ("next", Some(lifespan))
        } else if key_set.previous.is_none() {
            key_set.previous = Some(entry.raw.encode());
            ("previous", None)
        } else {
            eprintln!("#{idx}: too many keys for signing algorithm {alg}");
            fail = true;
            continue;
        };

        if let Some(lifespan) = lifespan {
            eprintln!(
                "#{idx}: found {alg} key, fingerprint: {fp} (as {purpose}, expires in {lifespan:?})"
            );
        } else {
            eprintln!("#{idx}: found {alg} key, fingerprint: {fp} (as {purpose})");
        }
    }
    if fail {
        eprintln!("Aborting because of errors");
        std::process::exit(1);
    }
    if key_sets.is_empty() {
        eprintln!("No private keys found");
        std::process::exit(1);
    }

    eprintln!("NOTE: Expiration times cannot be imported, and were reset");

    if dry_run {
        eprintln!("NOTE: Dry run, not applying changes");
    } else {
        let store = builder
            .into_store()
            .await
            .unwrap_or_else(|err| panic!("Failed to build configuration: {err}"));
        for (alg, key_set) in key_sets {
            store.send(ImportKeySet(key_set)).await;
            eprintln!("Successfully imported {alg} keys");
        }
    }

    // TODO: This is a little hacky, but we don't have code to shutdown gracefully.
    // (Currently, if a Redis store is simply dropped, the pubsub task panics.)
    std::process::exit(0);
}

async fn export_keys(builder: ConfigBuilder, path: &Path) {
    if builder.is_keyed_manually() {
        eprintln!("Exporting keys, but configuration uses manual keying.");
    }

    let mut writer: Box<dyn Write> = if path == Path::new("-") {
        Box::new(std::io::stdout())
    } else {
        Box::new(File::create(path).expect("Could not create file"))
    };

    let mut num: usize = 0;
    let signing_algs = builder.signing_algs.clone();
    let store = builder
        .into_store()
        .await
        .unwrap_or_else(|err| panic!("Failed to build configuration: {err}"));
    for alg in signing_algs {
        let key_set = store.send(ExportKeySet(alg)).await;
        if let Some(key) = key_set.current {
            writer
                .write_all(key.value.as_bytes())
                .expect("Write failed");
            num += 1;
        }
        if let Some(key) = key_set.next {
            writer
                .write_all(key.value.as_bytes())
                .expect("Write failed");
            num += 1;
        }
        if let Some(key) = key_set.previous {
            writer.write_all(key.as_bytes()).expect("Write failed");
            num += 1;
        }
    }
    if num == 0 {
        eprintln!("No private keys found in the store");
        std::process::exit(1);
    }
    writer.flush().expect("Flush failed");
    drop(writer);
    eprintln!("Exported {num} private keys");
    eprintln!("NOTE: The output does not contain expiration times");

    // TODO: This is a little hacky, but we don't have code to shutdown gracefully.
    // (Currently, if a Redis store is simply dropped, the pubsub task panics.)
    std::process::exit(0);
}
