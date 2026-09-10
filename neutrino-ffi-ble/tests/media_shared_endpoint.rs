// Copyright 2026 IndiaFOSS Companion contributors
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial.

//! Voice-over-mesh milestone 2 (companion ADR 0007, issue #13 "media ALPN on
//! the shared endpoint"): federation relay traffic and a full-duplex opus call
//! run concurrently over ONE iroh endpoint pair, with no cross-talk.
//!
//! `media_duplex.rs` proved duplex opus over a bare iroh connection on
//! endpoints of its own. On device that is the wrong shape: the endpoint that
//! matters is the federation one — it owns the node identity, the BLE custom
//! transport and the GATT→L2CAP upgrade — and a call that stood up a second
//! endpoint would bring up a second BLE link (or none). This test drives the
//! shipping transport (`IrohTransport`) and nothing else:
//!
//!   1. Two `IrohTransport`s A and B on loopback (relay off), exactly as
//!      `start_lan_with_peers` builds them. No other endpoint exists in this
//!      test, so every byte below crosses the one endpoint pair.
//!   2. Relay leg: A pushes federation-shaped datagrams to B through the
//!      `DatagramLink` seam (`send`/`recv`) at a steady pace, B answers each
//!      over the reused accepted connection — the real federation path.
//!   3. Media leg, concurrently: A `connect_media`s B (second ALPN, same
//!      endpoint), B `accept_media`s; then the four duplex tasks of
//!      `media_duplex.rs` (helpers copied, retargeted to `MediaConnection`):
//!      A sends 440 Hz, B sends 660 Hz, each drains the other's opus frames
//!      into a sequence-keyed jitter buffer with PLC.
//!   4. Gates: every relay datagram B saw is a relay datagram (tagged with A's
//!      authenticated id) and every reply A saw is a reply — never an opus
//!      frame; no media datagram carries the relay marker; both recovered
//!      tones correlate with their own source and not the other; the relay
//!      count is exact. That is "no cross-talk" at both layers: ALPN keeps the
//!      two QUIC connections apart, and the transport keeps the relay queue
//!      apart from the media leg.
//!   5. Clean and BLE-shaped (5 % loss, applied at the sender of both legs).
//!      `sim_link.rs` is the crate's BLE fault-injection seam, but it exists
//!      precisely because iroh migrates a connection *off* a userspace
//!      impairment proxy; it replaces the iroh medium rather than impairing
//!      it, so it cannot sit under a test whose point is the iroh endpoint.
//!      The sender-side loss model of `media_duplex.rs` is the BLE shape that
//!      does apply here.
//!
//! Loopback remains an upper bound on the transport; the on-device numbers
//! (real L2CAP throughput, a phone-to-phone call) are the open acceptance on
//! #13 and are not claimed here.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use neutrino_ble::relay_transport::{IrohTransport, MediaConnection};
use neutrino_main::{DatagramLink, LinkContext};
use opus::{Application, Channels, Decoder, Encoder};

const SAMPLE_RATE: u32 = 48_000;
const FRAME_SAMPLES: usize = 960; // 20 ms @ 48 kHz mono
const BITRATE: i32 = 24_000; // ~24 kbit/s, opus VoIP
const SEQ_HEADER: usize = 8; // u64 little-endian sequence number

const TONE_A_HZ: f64 = 440.0; // A -> B
const TONE_B_HZ: f64 = 660.0; // B -> A

/// Marker every relay datagram starts with, so a relay byte string can never be
/// mistaken for an opus frame and vice versa. Real federation datagrams are
/// CoAP; the marker stands in for "not media".
const RELAY_MARKER: &[u8] = b"NEUTRINO-RELAY:";
const REPLY_MARKER: &[u8] = b"NEUTRINO-REPLY:";

/// A [`LinkContext`] with test doubles for the BLE-only members (same as the
/// transport's own unit tests): an empty display-name watch, a fresh registry,
/// and a command sender nobody listens to.
fn test_ctx(secret: [u8; 32]) -> LinkContext {
    LinkContext {
        secret,
        display_name: tokio::sync::watch::channel(String::new()).1,
        discovery: Arc::new(neutrino_main::DiscoveryRegistry::new()),
        commands: tokio::sync::mpsc::unbounded_channel().0,
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Deterministic xorshift PRNG (as in the probes). Degenerate at 0.
struct Rng(u64);
impl Rng {
    fn next_f64(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

// ---- opus helpers, copied from tests/media_duplex.rs -----------------------

fn sine_pcm(frames: usize, hz: f64) -> Vec<i16> {
    let amp = (i16::MAX as f64) * 0.3;
    (0..frames * FRAME_SAMPLES)
        .map(|n| {
            let t = n as f64 / SAMPLE_RATE as f64;
            (amp * (2.0 * std::f64::consts::PI * hz * t).sin()) as i16
        })
        .collect()
}

fn encode_tone(pcm: &[i16], frames: usize) -> Vec<Vec<u8>> {
    let mut enc =
        Encoder::new(SAMPLE_RATE, Channels::Mono, Application::Voip).expect("opus encoder");
    enc.set_bitrate(opus::Bitrate::Bits(BITRATE))
        .expect("set bitrate");
    (0..frames)
        .map(|f| {
            let start = f * FRAME_SAMPLES;
            enc.encode_vec(&pcm[start..start + FRAME_SAMPLES], 4000)
                .expect("opus encode")
        })
        .collect()
}

fn best_xcorr(a: &[f64], b: &[f64], max_lag: usize) -> (f64, usize) {
    let mut best = f64::MIN;
    let mut best_lag = 0;
    for lag in 0..=max_lag {
        if lag >= b.len() {
            break;
        }
        let n = (a.len()).min(b.len() - lag);
        if n == 0 {
            break;
        }
        let (mut sab, mut saa, mut sbb) = (0.0, 0.0, 0.0);
        for i in 0..n {
            let x = a[i];
            let y = b[i + lag];
            sab += x * y;
            saa += x * x;
            sbb += y * y;
        }
        if saa > 0.0 && sbb > 0.0 {
            let c = sab / (saa.sqrt() * sbb.sqrt());
            if c > best {
                best = c;
                best_lag = lag;
            }
        }
    }
    (best, best_lag)
}

fn snr_db(reference: &[f64], recovered: &[f64], lag: usize) -> f64 {
    if lag >= recovered.len() {
        return f64::NEG_INFINITY;
    }
    let n = reference.len().min(recovered.len() - lag);
    let (mut sxy, mut syy, mut sxx) = (0.0, 0.0, 0.0);
    for i in 0..n {
        let x = reference[i];
        let y = recovered[i + lag];
        sxy += x * y;
        syy += y * y;
        sxx += x * x;
    }
    if syy == 0.0 || sxx == 0.0 {
        return f64::NEG_INFINITY;
    }
    let gain = sxy / syy;
    let mut noise = 0.0;
    for i in 0..n {
        let d = reference[i] - gain * recovered[i + lag];
        noise += d * d;
    }
    if noise == 0.0 {
        return f64::INFINITY;
    }
    10.0 * (sxx / noise).log10()
}

/// Pace one direction's opus packets out as sequence-tagged frames over the
/// shared endpoint's media leg, dropping some per the loss model. Returns the
/// delivered count.
async fn send_stream(media: MediaConnection, packets: Vec<Vec<u8>>, loss: f64, seed: u64) -> usize {
    let interval = Duration::from_secs_f64(FRAME_SAMPLES as f64 / SAMPLE_RATE as f64);
    let mut rng = Rng(seed);
    let mut delivered = 0usize;
    for (seq, packet) in packets.iter().enumerate() {
        if loss > 0.0 && rng.next_f64() < loss {
            tokio::time::sleep(interval).await;
            continue;
        }
        let mut buf = BytesMut::with_capacity(SEQ_HEADER + packet.len());
        buf.put_u64_le(seq as u64);
        buf.extend_from_slice(packet);
        if media.send_frame(Bytes::from(buf)).is_ok() {
            delivered += 1;
        }
        tokio::time::sleep(interval).await;
    }
    delivered
}

/// Drain the peer's frames into a jitter buffer keyed by sequence until the leg
/// closes. Also returns every raw datagram, so the cross-talk gate can inspect
/// what actually arrived on the media leg.
async fn recv_stream(media: MediaConnection) -> (HashMap<u64, Vec<u8>>, Vec<Bytes>) {
    let mut jitter: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut raw = Vec::new();
    while let Ok(dgram) = media.recv_frame().await {
        raw.push(dgram.clone());
        if dgram.len() >= SEQ_HEADER {
            let seq = u64::from_le_bytes(dgram[..SEQ_HEADER].try_into().unwrap());
            jitter.insert(seq, dgram[SEQ_HEADER..].to_vec());
        }
    }
    (jitter, raw)
}

fn decode_stream(jitter: &HashMap<u64, Vec<u8>>, frames: usize) -> (Vec<i16>, usize) {
    let mut dec = Decoder::new(SAMPLE_RATE, Channels::Mono).expect("opus decoder");
    let mut out = Vec::with_capacity(frames * FRAME_SAMPLES);
    let mut concealed = 0usize;
    let mut scratch = vec![0i16; FRAME_SAMPLES];
    for seq in 0..frames as u64 {
        let n = match jitter.get(&seq) {
            Some(pkt) => dec.decode(pkt, &mut scratch, false).expect("opus decode"),
            None => {
                concealed += 1;
                match dec.decode(&[], &mut scratch, false) {
                    Ok(n) => n,
                    Err(_) => {
                        for s in scratch.iter_mut() {
                            *s = 0;
                        }
                        FRAME_SAMPLES
                    }
                }
            }
        };
        out.extend_from_slice(&scratch[..n]);
    }
    (out, concealed)
}

struct Leg {
    delivered: usize,
    concealed: usize,
    out_samples: usize,
    own_xcorr: f64,
    own_lag: usize,
    own_snr_db: f64,
    cross_xcorr: f64,
}

fn score_leg(
    out: &[i16],
    concealed: usize,
    delivered: usize,
    own_ref: &[i16],
    cross_ref: &[i16],
) -> Leg {
    let skip = 3 * FRAME_SAMPLES;
    let ownf: Vec<f64> = own_ref[skip..].iter().map(|&s| s as f64).collect();
    let crossf: Vec<f64> = cross_ref[skip..].iter().map(|&s| s as f64).collect();
    let recf: Vec<f64> = out[skip.min(out.len())..]
        .iter()
        .map(|&s| s as f64)
        .collect();
    let (own_xcorr, own_lag) = best_xcorr(&ownf, &recf, 2000);
    let own_snr_db = snr_db(&ownf, &recf, own_lag);
    let (cross_xcorr, _) = best_xcorr(&crossf, &recf, 2000);
    Leg {
        delivered,
        concealed,
        out_samples: out.len(),
        own_xcorr,
        own_lag,
        own_snr_db,
        cross_xcorr,
    }
}

fn report(tag: &str, dir: &str, leg: &Leg) {
    eprintln!(
        "{tag:11} media {dir}: delivered {} concealed {} out {} samples | own xcorr {:.3} (lag {}) SNR {:.1} dB | cross xcorr {:.3}",
        leg.delivered,
        leg.concealed,
        leg.out_samples,
        leg.own_xcorr,
        leg.own_lag,
        leg.own_snr_db,
        leg.cross_xcorr,
    );
}

/// Same gates as `media_duplex.rs`: alignment, accounting, own-signal
/// correlation, anti-cross-talk between the two tones.
fn assert_leg(tag: &str, dir: &str, leg: &Leg, frames: usize, loss: bool) {
    assert_eq!(
        leg.out_samples,
        frames * FRAME_SAMPLES,
        "{tag} {dir}: recovered length must be exactly N x {FRAME_SAMPLES} samples",
    );
    if loss {
        assert!(
            leg.concealed > 0,
            "{tag} {dir}: loss model dropped nothing — not exercising concealment",
        );
        assert_eq!(
            leg.delivered + leg.concealed,
            frames,
            "{tag} {dir}: delivered + concealed must account for every sequence",
        );
        assert!(
            leg.own_xcorr > 0.3,
            "{tag} {dir}: own correlation {:.3} collapsed",
            leg.own_xcorr,
        );
    } else {
        assert_eq!(leg.delivered, frames, "{tag} {dir}: no frame should drop");
        assert_eq!(leg.concealed, 0, "{tag} {dir}: nothing to conceal");
        assert!(
            leg.own_xcorr > 0.8,
            "{tag} {dir}: own correlation {:.3} below 0.8",
            leg.own_xcorr,
        );
    }
    assert!(
        leg.cross_xcorr < 0.2,
        "{tag} {dir}: cross-talk — correlates {:.3} with the OTHER tone",
        leg.cross_xcorr,
    );
    assert!(
        leg.own_xcorr > leg.cross_xcorr + 0.3,
        "{tag} {dir}: own {:.3} not clearly above cross {:.3}",
        leg.own_xcorr,
        leg.cross_xcorr,
    );
}

// ---- relay leg --------------------------------------------------------------

struct RelayOutcome {
    sent: usize,
    /// (source tag, payload) of everything B's `DatagramLink::recv` yielded.
    at_b: Vec<(Vec<u8>, Vec<u8>)>,
    replied: usize,
    at_a: Vec<(Vec<u8>, Vec<u8>)>,
}

/// A → B federation-shaped datagrams through the seam at a steady pace (with
/// the loss model applied at A's sender), B replying to each over the reused
/// accepted connection. Runs for the duration of the call; ends when `stop`
/// fires and the tails have drained.
async fn run_relay(
    a: Arc<IrohTransport>,
    b: Arc<IrohTransport>,
    count: usize,
    loss: f64,
    seed: u64,
) -> RelayOutcome {
    let a_addr = hex32(&a.node_key()).into_bytes();
    let b_addr = hex32(&b.node_key()).into_bytes();

    // B: receive relay datagrams, reply to each. Stops after `idle` with no
    // traffic once the sender is done — the datagram seam has no end-of-stream.
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<()>();
    let b_task = {
        let b = Arc::clone(&b);
        let a_addr = a_addr.clone();
        tokio::spawn(async move {
            let mut at_b = Vec::new();
            let mut replied = 0usize;
            let idle = Duration::from_millis(400);
            loop {
                match tokio::time::timeout(idle, b.recv()).await {
                    Ok(Some((src, payload))) => {
                        // Reply over the connection A dialed (B never seeded A).
                        let mut reply = REPLY_MARKER.to_vec();
                        reply.extend_from_slice(&payload[RELAY_MARKER.len().min(payload.len())..]);
                        if b.send(&a_addr, &reply).await.is_ok() {
                            replied += 1;
                        }
                        at_b.push((src, payload));
                    }
                    Ok(None) => break,
                    Err(_) => {
                        if done_rx.try_recv().is_ok() {
                            break;
                        }
                    }
                }
            }
            (at_b, replied)
        })
    };
    // A: collect replies; same idle rule, released by the sender's done signal.
    let (a_done_tx, mut a_done_rx) = tokio::sync::oneshot::channel::<()>();
    let a_task = {
        let a = Arc::clone(&a);
        tokio::spawn(async move {
            let mut at_a = Vec::new();
            let idle = Duration::from_millis(400);
            loop {
                match tokio::time::timeout(idle, a.recv()).await {
                    Ok(Some(item)) => at_a.push(item),
                    Ok(None) => break,
                    Err(_) => {
                        if a_done_rx.try_recv().is_ok() {
                            break;
                        }
                    }
                }
            }
            at_a
        })
    };

    // A: the sender. 20 ms pace — the same cadence as the media frames, so the
    // two legs interleave datagram for datagram on the wire.
    let mut rng = Rng(seed);
    let mut sent = 0usize;
    for i in 0..count {
        if loss > 0.0 && rng.next_f64() < loss {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        }
        let mut payload = RELAY_MARKER.to_vec();
        payload.extend_from_slice(format!("{i:05}").as_bytes());
        a.send(&b_addr, &payload).await.expect("relay send A->B");
        sent += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Let the tails drain, then release both collectors.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = done_tx.send(());
    let _ = a_done_tx.send(());
    let (at_b, replied) = b_task.await.expect("B relay task");
    let at_a = a_task.await.expect("A relay task");
    RelayOutcome {
        sent,
        at_b,
        replied,
        at_a,
    }
}

// ---- the combined run -------------------------------------------------------

struct Outcome {
    relay: RelayOutcome,
    a_to_b: Leg,
    b_to_a: Leg,
    /// Raw media datagrams seen at each end (for the cross-talk gate).
    media_raw_at_a: Vec<Bytes>,
    media_raw_at_b: Vec<Bytes>,
}

async fn run(frames: usize, loss: f64, seeds: [u64; 3]) -> Outcome {
    let loopback: SocketAddr = "127.0.0.1:0".parse().expect("loopback");
    let a = IrohTransport::bind(test_ctx([0xA1; 32]), loopback)
        .await
        .expect("bind A");
    let b = IrohTransport::bind(test_ctx([0xB2; 32]), loopback)
        .await
        .expect("bind B");
    // A learns B's address once — exactly as `start_lan_with_peers` seeds a
    // configured peer. B learns A only by accepting (relay) and by accepting
    // (media): nothing else is seeded.
    let b_sock = b
        .bound_sockets()
        .into_iter()
        .find(|s| s.ip().is_loopback())
        .expect("B has a loopback socket");
    a.seed_peer(b.node_key(), b_sock);

    // --- media leg on the SAME endpoints: A dials on the media ALPN, B accepts.
    let (media_a, media_b) = tokio::join!(
        async {
            a.connect_media(b.node_key())
                .await
                .expect("A connects media to B over the shared endpoint")
        },
        async {
            tokio::time::timeout(Duration::from_secs(10), b.accept_media())
                .await
                .expect("B accepts media in time")
                .expect("B's transport is open")
        },
    );
    assert_eq!(
        media_a.remote_node(),
        b.node_key(),
        "media leg authenticated to B"
    );
    assert_eq!(
        media_b.remote_node(),
        a.node_key(),
        "media leg authenticated to A"
    );
    assert!(
        media_a.max_frame_size().unwrap_or(0) > SEQ_HEADER + 200,
        "media path carries an opus frame in one datagram"
    );

    let pcm_a = sine_pcm(frames, TONE_A_HZ);
    let pcm_b = sine_pcm(frames, TONE_B_HZ);
    let packets_a = encode_tone(&pcm_a, frames);
    let packets_b = encode_tone(&pcm_b, frames);

    // --- everything at once: relay A<->B, media A->B, media B->A.
    let recv_at_a = tokio::spawn(recv_stream(media_a.clone())); // B's 660
    let recv_at_b = tokio::spawn(recv_stream(media_b.clone())); // A's 440
    let send_a = tokio::spawn(send_stream(media_a.clone(), packets_a, loss, seeds[0]));
    let send_b = tokio::spawn(send_stream(media_b.clone(), packets_b, loss, seeds[1]));
    // The relay leg runs for the whole call: as many datagrams as frames, at
    // the same cadence.
    let relay = tokio::spawn(run_relay(
        Arc::clone(&a),
        Arc::clone(&b),
        frames,
        loss,
        seeds[2],
    ));

    let delivered_a = send_a.await.expect("send A task");
    let delivered_b = send_b.await.expect("send B task");
    let relay = relay.await.expect("relay task");

    // Drain, then hang up; both recv loops end on close.
    tokio::time::sleep(Duration::from_millis(300)).await;
    media_a.close();
    media_b.close();
    let (jitter_at_a, media_raw_at_a) = recv_at_a.await.expect("recv A task");
    let (jitter_at_b, media_raw_at_b) = recv_at_b.await.expect("recv B task");

    let (out_at_b, concealed_b) = decode_stream(&jitter_at_b, frames);
    let (out_at_a, concealed_a) = decode_stream(&jitter_at_a, frames);
    let a_to_b = score_leg(&out_at_b, concealed_b, delivered_a, &pcm_a, &pcm_b);
    let b_to_a = score_leg(&out_at_a, concealed_a, delivered_b, &pcm_b, &pcm_a);

    // The endpoints outlive the call: the federation link is not torn down by a
    // hang-up. Prove it with one more relay round-trip after the media closed.
    let a_addr = hex32(&a.node_key()).into_bytes();
    let b_addr = hex32(&b.node_key()).into_bytes();
    a.send(&b_addr, b"NEUTRINO-RELAY:after-call")
        .await
        .expect("relay still works after hang-up");
    let (src, got) = tokio::time::timeout(Duration::from_secs(10), b.recv())
        .await
        .expect("post-call relay datagram arrives")
        .expect("B link open");
    assert_eq!(src, a_addr);
    assert_eq!(got, b"NEUTRINO-RELAY:after-call");

    Outcome {
        relay,
        a_to_b,
        b_to_a,
        media_raw_at_a,
        media_raw_at_b,
    }
}

fn assert_relay(tag: &str, o: &Outcome, a_hex: &[u8], b_hex: &[u8]) {
    let r = &o.relay;
    eprintln!(
        "{tag:11} relay: sent {} received-at-B {} replied {} replies-at-A {}",
        r.sent,
        r.at_b.len(),
        r.replied,
        r.at_a.len()
    );
    // Exact accounting over loopback: every relay datagram A put on the wire
    // reached B's `recv`, and every reply reached A's. (Loss is modelled at the
    // sender, so `sent` already excludes dropped ones.)
    assert_eq!(
        r.at_b.len(),
        r.sent,
        "{tag}: relay datagrams A->B lost in transit"
    );
    assert_eq!(
        r.replied, r.sent,
        "{tag}: B failed to reply to some relay datagram"
    );
    assert_eq!(
        r.at_a.len(),
        r.replied,
        "{tag}: relay replies B->A lost in transit"
    );
    assert!(r.sent > 0, "{tag}: relay leg sent nothing");
    // Cross-talk, relay side: nothing but relay payloads on the seam, each
    // tagged with the peer's authenticated id.
    for (src, payload) in &r.at_b {
        assert_eq!(src, a_hex, "{tag}: relay datagram at B tagged with A's id");
        assert!(
            payload.starts_with(RELAY_MARKER),
            "{tag}: non-relay bytes on B's federation queue: {payload:?}"
        );
    }
    for (src, payload) in &r.at_a {
        assert_eq!(src, b_hex, "{tag}: reply at A tagged with B's id");
        assert!(
            payload.starts_with(REPLY_MARKER),
            "{tag}: non-reply bytes on A's federation queue: {payload:?}"
        );
    }
    // Cross-talk, media side: no relay bytes ever reached a media leg.
    for d in o.media_raw_at_a.iter().chain(&o.media_raw_at_b) {
        assert!(
            !d.starts_with(RELAY_MARKER) && !d.starts_with(REPLY_MARKER),
            "{tag}: relay datagram leaked onto the media leg"
        );
        assert!(d.len() > SEQ_HEADER, "{tag}: malformed media frame");
    }
}

#[tokio::test]
async fn relay_and_duplex_opus_share_one_endpoint_pair_without_cross_talk() {
    const FRAMES: usize = 100; // 2 s of audio per direction, 100 relay datagrams

    // Node ids are derived from the fixed secrets above, so they are stable.
    let a_hex = hex32(
        &ed25519_dalek::SigningKey::from_bytes(&[0xA1; 32])
            .verifying_key()
            .to_bytes(),
    );
    let b_hex = hex32(
        &ed25519_dalek::SigningKey::from_bytes(&[0xB2; 32])
            .verifying_key()
            .to_bytes(),
    );

    // --- clean.
    let clean = run(
        FRAMES,
        0.0,
        [
            0x9E37_79B9_7F4A_7C15,
            0xD1B5_4A32_D192_ED03,
            0x5851_F42D_4C95_7F2D,
        ],
    )
    .await;
    report("clean", "A->B", &clean.a_to_b);
    report("clean", "B->A", &clean.b_to_a);
    assert_leg("clean", "A->B", &clean.a_to_b, FRAMES, false);
    assert_leg("clean", "B->A", &clean.b_to_a, FRAMES, false);
    assert_relay("clean", &clean, a_hex.as_bytes(), b_hex.as_bytes());
    assert_eq!(
        clean.relay.sent, FRAMES,
        "clean: relay leg sends everything"
    );

    // --- BLE-shaped: 5 % loss at the sender of every leg.
    let lossy = run(
        FRAMES,
        0.05,
        [
            0x1234_5678_9ABC_DEF0,
            0x0FED_CBA9_8765_4321,
            0x2545_F491_4F6C_DD1D,
        ],
    )
    .await;
    report("BLE-shaped", "A->B", &lossy.a_to_b);
    report("BLE-shaped", "B->A", &lossy.b_to_a);
    assert_leg("BLE-shaped", "A->B", &lossy.a_to_b, FRAMES, true);
    assert_leg("BLE-shaped", "B->A", &lossy.b_to_a, FRAMES, true);
    assert_relay("BLE-shaped", &lossy, a_hex.as_bytes(), b_hex.as_bytes());
    assert!(
        lossy.relay.sent < FRAMES,
        "BLE-shaped: the relay loss model dropped nothing — not exercising loss"
    );

    // Loss only degrades.
    assert!(lossy.a_to_b.own_xcorr <= clean.a_to_b.own_xcorr + 1e-6);
    assert!(lossy.b_to_a.own_xcorr <= clean.b_to_a.own_xcorr + 1e-6);
}

/// A media dial to a peer nobody is accepting calls from must fail at the
/// door — and must not disturb the relay path to that peer.
#[tokio::test]
async fn media_to_a_peer_that_is_not_listening_is_refused_but_relay_survives() {
    let loopback: SocketAddr = "127.0.0.1:0".parse().expect("loopback");
    let a = IrohTransport::bind(test_ctx([0xC3; 32]), loopback)
        .await
        .expect("bind A");
    let b = IrohTransport::bind(test_ctx([0xD4; 32]), loopback)
        .await
        .expect("bind B");
    let b_sock = b
        .bound_sockets()
        .into_iter()
        .find(|s| s.ip().is_loopback())
        .expect("B loopback socket");
    a.seed_peer(b.node_key(), b_sock);

    // Fill B's media accept queue without draining it: the (capacity+1)th call
    // is refused at the handshake by B's accept loop. The handshake itself
    // completes on A's side (ALPN is offered), so the failure surfaces as the
    // leg closing, not a dial error.
    let mut legs = Vec::new();
    for _ in 0..8 {
        if let Ok(leg) = a.connect_media(b.node_key()).await {
            legs.push(leg);
        }
    }
    let mut refused = 0;
    for leg in &legs {
        // A refused leg is closed by B; a queued one is still open.
        if let Ok(Err(_)) = tokio::time::timeout(Duration::from_millis(500), leg.recv_frame()).await
        {
            refused += 1;
        }
    }
    assert!(
        refused >= 1,
        "an overflowing call must be refused at the door"
    );
    assert!(
        legs.len() - refused <= 4,
        "no more than the accept capacity stays open"
    );

    // Relay unaffected.
    let b_addr = hex32(&b.node_key()).into_bytes();
    a.send(&b_addr, b"still-here").await.expect("relay send");
    let (_, got) = tokio::time::timeout(Duration::from_secs(10), b.recv())
        .await
        .expect("relay arrives")
        .expect("B open");
    assert_eq!(got, b"still-here");
}
