//! A desktop Neutrino node running the **iroh medium** — the real federation
//! transport, not a stand-in.
//!
//! Why this exists: everything that could be tested about the mesh until now
//! was tested against the wrong thing. `neutrino`'s own binary federates over
//! plain HTTP and carries no iroh medium at all, so a swarm built on it
//! measures the homeserver, not the transport. The medium itself lived only
//! inside a `cdylib` reachable from Android, which meant LAN discovery, path
//! selection and QUIC framing could be reasoned about but never *run* without
//! two handsets.
//!
//! This binary is the medium's `start_ble` twin for a machine with a keyboard:
//! same `neutrino::start_with` composition, same `IrohTransport`, same mDNS
//! discovery — minus the `ble` feature, which needs Android's JNI. Run two of
//! them on one laptop and they find each other over the LAN and federate, which
//! is the first time that claim can be checked rather than asserted.
//!
//! ```sh
//! # two nodes, each in its own storage dir; they discover each other by mDNS
//! neutrino-lan --bind 127.0.0.1:8101 --storage /tmp/lan-a
//! neutrino-lan --bind 127.0.0.1:8102 --storage /tmp/lan-b
//! ```
//!
//! It prints the node's `server_name` (the 64-hex node id) on the first line of
//! stdout once the server is ready, so a harness can key peers without parsing
//! logs.

use std::time::{Duration, Instant};

/// How long to wait for the server to report a `server_name` before giving up.
/// Generous: a first start creates the DB, derives the node secret and binds an
/// iroh endpoint.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

struct Args {
    bind: String,
    storage: String,
    localpart: String,
    /// `None` derives the name from the node identity, which is what a mesh
    /// node wants — the server name IS the public key.
    server_name: Option<String>,
    /// Public federation port for the in-process `neutrino-lb` sidecar.
    ///
    /// **Required for federation to use the mesh at all.** Without it the
    /// homeserver federates directly over HTTP to `http://{server_name}` — and
    /// a mesh server name is a 64-hex node id with no DNS behind it, so every
    /// outbound request dies as a 502 while discovery looks perfectly healthy.
    /// The sidecar is what routes federation through the `DatagramLink`, i.e.
    /// over iroh.
    fed_port: u16,
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().collect();
    let get = |name: &str| -> Option<String> {
        argv.iter()
            .position(|a| a == name)
            .and_then(|i| argv.get(i + 1))
            .cloned()
    };
    if argv.iter().any(|a| a == "-h" || a == "--help") {
        return Err(format!(
            "usage: {} --bind <addr:port> --storage <dir> --fed-port <port> \\\n            [--localpart n] [--server-name <name>]",
            argv.first().map(String::as_str).unwrap_or("neutrino-lan")
        ));
    }
    let bind = get("--bind").ok_or("missing --bind <addr:port>")?;
    let storage = get("--storage").ok_or("missing --storage <dir>")?;
    let fed_port = get("--fed-port")
        .ok_or("missing --fed-port <port> (without it federation never uses the mesh)")?
        .parse::<u16>()
        .map_err(|e| format!("--fed-port: {e}"))?;
    Ok(Args {
        bind,
        storage,
        localpart: get("--localpart").unwrap_or_else(|| "n".to_string()),
        server_name: get("--server-name"),
        fed_port,
    })
}

fn main() -> std::process::ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // Default to something readable; `RUST_LOG` still wins.
    if std::env::var_os("RUST_LOG").is_none() {
        // SAFETY: single-threaded, before any runtime or thread is spawned.
        unsafe { std::env::set_var("RUST_LOG", "warn,neutrino_ble=info") };
    }

    if let Err(e) = std::fs::create_dir_all(&args.storage) {
        eprintln!("cannot create storage dir {}: {e}", args.storage);
        return std::process::ExitCode::FAILURE;
    }

    let config = neutrino::NeutrinoConfig {
        bind_addr: args.bind.clone(),
        localpart: args.localpart,
        server_name: args.server_name,
        storage_dir: args.storage.clone(),
        outbound_concurrency: 8,
        // Must be false: a trusted-network node omits `hashes`, which the
        // reference hash covers, so it derives different event ids from every
        // other Matrix server. Signed is also the only mode that can ever
        // federate outward (see the companion's issue #129).
        trusted_network: false,
        // The whole point: routes outbound federation through the sidecar and
        // onto the iroh link. `None` here silently federates over plain HTTP to
        // a name with no DNS.
        lb_federation_port: Some(args.fed_port),
        log_dir: None,
        delivery_receipts: true,
    };

    let handle = neutrino_ble::start_lan(config);

    // Poll for readiness rather than sleeping a guess: the harness needs the
    // server name, and a start that refuses (e.g. the trust-domain guard on a
    // reused storage dir) must surface its error instead of hanging.
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if let Some(name) = handle.server_name() {
            // First line of stdout is the contract with the harness.
            println!("{name}");
            break;
        }
        if let Some(err) = handle.last_error() {
            eprintln!("neutrino refused to start: {err}");
            return std::process::ExitCode::FAILURE;
        }
        if Instant::now() >= deadline {
            eprintln!("neutrino did not report a server name within {READY_TIMEOUT:?}");
            return std::process::ExitCode::FAILURE;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!(
        "neutrino-lan cs-api {} federation :{} (storage {})",
        args.bind, args.fed_port, args.storage
    );

    // The server owns its own runtime and threads; park until killed. A harness
    // stops these with SIGTERM/SIGKILL, and the store is crash-safe by design
    // (the outbox is what a restart redelivers from).
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
