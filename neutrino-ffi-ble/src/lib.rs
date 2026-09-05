// Copyright (c) 2026 Element Creations Ltd.
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial.

//! The iroh/BLE federation medium for the embedded neutrino homeserver.
//!
//! This crate is a composition root, not an API: it provides the concrete
//! [`neutrino_main::DatagramLink`] (an iroh QUIC endpoint carrying one CoAP
//! datagram per unreliable QUIC datagram, over BLE on device — see
//! `relay_transport`) and injects it into the transport-agnostic FFI surface
//! via [`neutrino::start_with`]. The one export, [`start_ble`], is the
//! BLE-mesh twin of `neutrino::start` (the LAN/UDP build).
//!
//! The cdylib built from this crate carries both uniffi namespaces —
//! `neutrino_ble` (this file) and `neutrino` (the whole embedded API:
//! `NeutrinoConfig`, `NeutrinoHandle`, ...) — so uniffi-bindgen in library
//! mode over `libneutrino_ble.so` generates the complete Kotlin surface.

uniffi::setup_scaffolding!("neutrino_ble");

#[cfg(feature = "ble")]
mod ble_android;
mod relay_transport;

use relay_transport::{IrohTransport, RELAY_BIND};

/// Fixed localpart for every embedded peer's user: user ids are
/// `@n:{node_id}`. The discovery registry is localpart-agnostic — this is the
/// medium's convention, applied by whichever discovery drain (BLE or mDNS, see
/// `relay_transport`) learned the node id.
#[cfg(any(feature = "ble", feature = "mdns"))]
pub(crate) const DISCOVERY_LOCALPART: &str = "n";

/// Start the embedded homeserver with the iroh/BLE federation medium.
///
/// Identical contract to `neutrino::start` (spawned runtime, returned control
/// handle) with the datagram link factory injected: once the entrypoint has
/// resolved the node secret it binds an iroh endpoint whose id IS that
/// secret's ed25519 public key, dials peers by their link address (the
/// lowercase hex of their 32-byte node id — the peer's `server_name` bytes),
/// and (with the `ble` feature, i.e. on device) discovers + reaches them over
/// the BLE mesh.
#[uniffi::export]
pub fn start_ble(mut config: neutrino::NeutrinoConfig) -> neutrino::NeutrinoHandle {
    config.delivery_receipts = true;
    // Announce which upstream neutrino this .aar was compiled against (baked in
    // by build.rs from the lockfile). Install the logcat subscriber first so the
    // line is not dropped — idempotent, and start_with installs it again. Pass
    // the host's log directory through: whichever call runs first wins, so
    // omitting it here would leave the on-disk sink permanently uninstalled.
    neutrino_main::init_tracing(config.log_dir.as_deref().map(std::path::Path::new));
    tracing::info!(
        neutrino_commit = env!("NEUTRINO_COMMIT"),
        "neutrino BLE medium starting"
    );
    // iroh unifies reqwest's TLS backend to rustls with no default crypto
    // provider, so building the federation client would panic ("No rustls
    // crypto provider is configured"). The provider is a process-global the
    // composition root must install before the server (or iroh) builds any
    // client. Idempotent: `install_default` errs if one is set; ignored.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let factory: neutrino_main::FederationLinkFactory = Box::new(move |ctx| {
        Box::pin(async move {
            let transport = IrohTransport::bind(ctx, RELAY_BIND).await?;
            Ok(neutrino_main::FederationLink::new(
                transport as std::sync::Arc<dyn neutrino_main::DatagramLink>,
            )
            .with_key_resolver(std::sync::Arc::new(neutrino_main::NodeIdKeyResolver)))
        })
    });
    // No runtime and no store: this medium declares no room version, so it keeps
    // no persistent state of its own and needs neither handle before the call —
    // neutrino builds the runtime and opens the store itself.
    neutrino::start_with(config, None, None, Some(factory))
}

/// Start the embedded homeserver with the iroh medium on a machine that is not
/// a phone — same composition as [`start_ble`], minus BLE.
///
/// This is what makes the medium testable. Off Android the `ble` feature is
/// absent (its backend needs JNI, or D-Bus/BlueZ on Linux), so the endpoint is
/// IP-only: QUIC over whatever interfaces are up, with peers found by mDNS. Two
/// of these on one LAN discover each other and federate, which is the only way
/// to exercise discovery, path selection and the CoAP framing without two
/// handsets in hand.
///
/// Not `#[uniffi::export]`ed: nothing across the FFI wants it, and exporting a
/// second entrypoint would put a desktop-only path in the Kotlin surface.
pub fn start_lan(config: neutrino::NeutrinoConfig) -> neutrino::NeutrinoHandle {
    start_lan_on(config, RELAY_BIND)
}

/// [`start_lan`] with an explicit QUIC bind address.
///
/// Exists for test rigs that run many nodes on one host: bound to the default
/// wildcard every node advertises the same host addresses and differs only by
/// port, which is not a topology iroh is designed for. A distinct loopback
/// alias per node gives disjoint address sets.
pub fn start_lan_on(
    config: neutrino::NeutrinoConfig,
    relay_bind: std::net::SocketAddr,
) -> neutrino::NeutrinoHandle {
    start_lan_with_peers(config, relay_bind, Vec::new())
}

/// [`start_lan_on`] with peers seeded explicitly, bypassing discovery.
///
/// mDNS is link-local, so it finds nothing across a routed network — and on a
/// Wi-Fi with client isolation (the default on most guest and conference APs)
/// peers cannot reach each other over the LAN at all, even on one subnet, while
/// multicast still leaks enough for discovery to *look* healthy. Explicit peers
/// are how a node reaches another across those boundaries, and they are the
/// mechanism a venue gateway would be configured with: `[federation] peers` on
/// the Spindle side has exactly this shape.
pub fn start_lan_with_peers(
    mut config: neutrino::NeutrinoConfig,
    relay_bind: std::net::SocketAddr,
    peers: Vec<([u8; 32], std::net::SocketAddr)>,
) -> neutrino::NeutrinoHandle {
    config.delivery_receipts = true;
    neutrino_main::init_tracing(config.log_dir.as_deref().map(std::path::Path::new));
    tracing::info!(
        neutrino_commit = env!("NEUTRINO_COMMIT"),
        ble = cfg!(feature = "ble"),
        "neutrino LAN medium starting"
    );
    // Same rustls provider requirement as `start_ble`: iroh unifies reqwest onto
    // rustls with no default provider, and the federation client would panic
    // without one. Idempotent.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let factory: neutrino_main::FederationLinkFactory = Box::new(move |ctx| {
        Box::pin(async move {
            let transport = IrohTransport::bind(ctx, relay_bind).await?;
            // Seeded before the link is handed over, so the first federation
            // request already has an address and does not burn a dial timeout.
            for (id, addr) in peers {
                transport.seed_peer(id, addr);
            }
            Ok(neutrino_main::FederationLink::new(
                transport as std::sync::Arc<dyn neutrino_main::DatagramLink>,
            )
            .with_key_resolver(std::sync::Arc::new(neutrino_main::NodeIdKeyResolver)))
        })
    });
    neutrino::start_with(config, None, None, Some(factory))
}
