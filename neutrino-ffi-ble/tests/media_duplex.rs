// Copyright 2026 IndiaFOSS Companion contributors
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial.

//! Voice-over-mesh milestone 2 (companion ADR 0007, issue #13 "duplex"): prove
//! the codec+framing path works in BOTH directions at once over a single iroh
//! connection, so a real 1:1 call — not just a one-way stream — round-trips.
//!
//! `media_codec.rs` (milestone 1) proved ONE-WAY opus: a 440 Hz tone A→B through
//! opus over sequence-tagged iroh datagrams with a PLC jitter buffer. It says
//! nothing about a live call, where each peer encodes and sends its own audio
//! *while* decoding the other's on the same connection. This test closes that
//! gap, still on loopback and with no audio hardware:
//!
//!   1. Two iroh endpoints A and B on loopback, media ALPN, relay off. One
//!      QUIC connection; both ends send and receive datagrams (datagrams are
//!      symmetric on a connection).
//!   2. Two DISTINCT signals run concurrently: A sends a 440 Hz tone, B sends a
//!      660 Hz tone, each encoded with its own opus encoder at ~24 kbit/s VoIP.
//!   3. Each side runs a send task and a receive task concurrently (tokio):
//!      it paces out its own opus frames as sequence-tagged datagrams while a
//!      sibling task drains the peer's frames into a sequence-keyed jitter
//!      buffer — the same u64-header framing and PLC contract as milestone 1.
//!   4. Both recovered streams are scored against BOTH references: each must
//!      correlate strongly with its OWN source and weakly with the OTHER. A
//!      440 Hz tone must never reconstruct as 660 Hz — that anti-cross-talk gate
//!      is what makes "duplex" mean two independent streams, not one echoed.
//!   5. Run clean (0 % loss) and BLE-shaped (5 % loss). Under loss each
//!      direction independently conceals its own gaps, stays frame-aligned, and
//!      only degrades — no panic, no stream confusion.
//!
//! Loopback is an upper bound on the transport, not a model of a real BLE link;
//! what it rules out is a duplex codec+framing path that cannot even carry two
//! independent streams at once on loopback. The impairment model injects loss at
//! the sender (as milestone 1 does) but no latency: the jitter buffer drains to
//! end-of-stream before decode, so a constant added delay is absorbed and
//! changes nothing measurable — modelling latency here would be sleep theatre.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use iroh::endpoint::presets::N0DisableRelay;
use iroh::{Endpoint, EndpointAddr, SecretKey};
use opus::{Application, Channels, Decoder, Encoder};

// Same second ALPN the throughput/codec probes use: media rides its own
// protocol on the shared iroh endpoint, apart from federation traffic.
const MEDIA_ALPN: &[u8] = b"neutrino/media-probe/0";

const SAMPLE_RATE: u32 = 48_000;
const FRAME_SAMPLES: usize = 960; // 20 ms @ 48 kHz mono
const BITRATE: i32 = 24_000; // ~24 kbit/s, opus VoIP
const SEQ_HEADER: usize = 8; // u64 little-endian sequence number

// The two independent call legs. Distinct frequencies so a stream that
// reconstructed as the wrong tone shows up as a cross-correlation spike.
const TONE_A_HZ: f64 = 440.0; // A -> B
const TONE_B_HZ: f64 = 660.0; // B -> A

/// Copied from `media_throughput.rs`/`media_codec.rs` (the task says copy, don't
/// refactor the shipping crate): a fresh iroh endpoint bound to an ephemeral
/// loopback port, speaking only the media ALPN, relay disabled.
async fn bind_loopback() -> Endpoint {
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("valid loopback addr");
    Endpoint::builder(N0DisableRelay)
        .secret_key(SecretKey::generate())
        .alpns(vec![MEDIA_ALPN.to_vec()])
        .bind_addr(addr)
        .expect("loopback bind addr accepted")
        .bind()
        .await
        .expect("endpoint binds")
}

/// Deterministic xorshift PRNG, seeded per run so the loss pattern is
/// reproducible (same shape as the throughput/codec probes' `Rng`). Degenerate
/// at state 0, so every seed used here is a large nonzero constant.
struct Rng(u64);
impl Rng {
    fn next_f64(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// A pure sine tone at `hz` as i16 PCM: `frames` blocks of `FRAME_SAMPLES`.
fn sine_pcm(frames: usize, hz: f64) -> Vec<i16> {
    let amp = (i16::MAX as f64) * 0.3;
    (0..frames * FRAME_SAMPLES)
        .map(|n| {
            let t = n as f64 / SAMPLE_RATE as f64;
            (amp * (2.0 * std::f64::consts::PI * hz * t).sin()) as i16
        })
        .collect()
}

/// Encode a PCM tone into per-frame opus packets at the VoIP bitrate.
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

/// Best normalised cross-correlation of `a` against `b` over integer lags
/// `0..=max_lag` (b delayed relative to a — opus adds ~6.5 ms of look-ahead, so
/// the recovered signal trails the input). Scale-invariant, in [-1, 1].
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

/// SNR (dB) of `recovered` vs `reference` after aligning by `lag` and fitting a
/// single gain that minimises residual energy (opus is not gain-preserving).
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
    let gain = sxy / syy; // scale recovered onto reference
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

/// Pace one direction's opus packets out as sequence-tagged datagrams, dropping
/// some per the loss model (no retransmit — the RTP contract). Returns the
/// delivered count. `&self` on send/read means the cloned `Connection` handle
/// carries both directions concurrently.
async fn send_stream(
    conn: iroh::endpoint::Connection,
    packets: Vec<Vec<u8>>,
    loss: f64,
    seed: u64,
) -> usize {
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
        if conn.send_datagram(Bytes::from(buf)).is_ok() {
            delivered += 1;
        }
        tokio::time::sleep(interval).await;
    }
    delivered
}

/// Drain the peer's datagrams into a jitter buffer keyed by sequence until the
/// connection closes (locally or by the peer). Runs concurrently with this
/// side's own `send_stream`.
async fn recv_stream(conn: iroh::endpoint::Connection) -> HashMap<u64, Vec<u8>> {
    let mut jitter: HashMap<u64, Vec<u8>> = HashMap::new();
    while let Ok(dgram) = conn.read_datagram().await {
        let seq = u64::from_le_bytes(dgram[..SEQ_HEADER].try_into().unwrap());
        jitter.insert(seq, dgram[SEQ_HEADER..].to_vec());
    }
    jitter
}

/// Walk every sequence `0..frames` in order out of one jitter buffer, opus-
/// decoding each, concealing any sequence that never arrived. Returns the
/// recovered PCM and the concealed-frame count. One decoder per stream: opus is
/// stateful and the two legs must not share decode state.
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
                // libopus PLC: an empty input slice conceals one lost frame.
                // If the crate rejects that, fall back to a silent frame — the
                // length invariant (one frame of output per sequence) holds
                // either way.
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

/// One recovered call leg, scored against both references.
struct Leg {
    delivered: usize,
    concealed: usize,
    out_samples: usize,
    own_xcorr: f64,
    own_lag: usize,
    own_snr_db: f64,
    cross_xcorr: f64,
}

/// Score a recovered stream against its OWN source tone and the OTHER tone.
/// Skips the encoder startup transient (first 3 frames), like milestone 1.
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
    // Cross-talk gate: max over the same lag search, so the low number is not an
    // artefact of a single unlucky lag — it is the *best* the wrong tone can do.
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

struct DuplexOutcome {
    a_to_b: Leg, // A's 440 Hz recovered at B
    b_to_a: Leg, // B's 660 Hz recovered at A
}

/// Full duplex round-trip: stand up A and B, run both legs concurrently, and
/// score each recovered stream against both tones.
async fn run_duplex(frames: usize, loss: f64, seed_a: u64, seed_b: u64) -> DuplexOutcome {
    let pcm_a = sine_pcm(frames, TONE_A_HZ);
    let pcm_b = sine_pcm(frames, TONE_B_HZ);
    let packets_a = encode_tone(&pcm_a, frames);
    let packets_b = encode_tone(&pcm_b, frames);

    // --- transport: A dials, B accepts; both endpoints stay owned here for the
    // whole call so neither drops and tears the connection down. ---
    let ep_a = bind_loopback().await;
    let ep_b = bind_loopback().await;
    let b_id = ep_b.id();
    let b_sock = *ep_b
        .bound_sockets()
        .iter()
        .find(|s| s.ip().is_loopback())
        .expect("a loopback bound socket");
    let addr = EndpointAddr::new(b_id).with_ip_addr(b_sock);

    let (conn_a, incoming_b) = tokio::join!(
        async { ep_a.connect(addr, MEDIA_ALPN).await.expect("connect") },
        async {
            ep_b.accept()
                .await
                .expect("incoming")
                .await
                .expect("accepted")
        },
    );
    let conn_b = incoming_b;

    // --- four concurrent tasks: each side sends its own tone and receives the
    // peer's on the same connection. ---
    let recv_at_a = tokio::spawn(recv_stream(conn_a.clone())); // collects B's 660
    let recv_at_b = tokio::spawn(recv_stream(conn_b.clone())); // collects A's 440
    let send_a = tokio::spawn(send_stream(conn_a.clone(), packets_a, loss, seed_a));
    let send_b = tokio::spawn(send_stream(conn_b.clone(), packets_b, loss, seed_b));

    let delivered_a = send_a.await.expect("send A task");
    let delivered_b = send_b.await.expect("send B task");

    // Let the last datagrams of both legs drain, THEN close — closing before the
    // settle would kill in-flight datagrams with the connection. Closing either
    // end ends both recv loops (locally-closed on this side, peer-closed on the
    // other), so neither `recv.await` can hang.
    tokio::time::sleep(Duration::from_millis(300)).await;
    conn_a.close(0u32.into(), b"done");
    conn_b.close(0u32.into(), b"done");
    let jitter_at_a = recv_at_a.await.expect("recv A task"); // B's 660
    let jitter_at_b = recv_at_b.await.expect("recv B task"); // A's 440

    let (out_at_b, concealed_b) = decode_stream(&jitter_at_b, frames); // A's 440 at B
    let (out_at_a, concealed_a) = decode_stream(&jitter_at_a, frames); // B's 660 at A

    // A's 440 recovered at B: own ref is 440, cross ref is 660.
    let a_to_b = score_leg(&out_at_b, concealed_b, delivered_a, &pcm_a, &pcm_b);
    // B's 660 recovered at A: own ref is 660, cross ref is 440.
    let b_to_a = score_leg(&out_at_a, concealed_a, delivered_b, &pcm_b, &pcm_a);

    DuplexOutcome { a_to_b, b_to_a }
}

fn report(tag: &str, dir: &str, leg: &Leg) {
    eprintln!(
        "{tag:11} {dir}: delivered {} concealed {} out {} samples | own xcorr {:.3} (lag {}) SNR {:.1} dB | cross xcorr {:.3}",
        leg.delivered,
        leg.concealed,
        leg.out_samples,
        leg.own_xcorr,
        leg.own_lag,
        leg.own_snr_db,
        leg.cross_xcorr,
    );
}

/// Per-direction alignment/accounting + own-signal correlation + anti-cross-talk
/// gate. `loss` toggles the clean vs BLE-shaped expectations.
fn assert_leg(tag: &str, dir: &str, leg: &Leg, frames: usize, loss: bool) {
    // Exact alignment: one decoded frame per sequence, gaps included.
    assert_eq!(
        leg.out_samples,
        frames * FRAME_SAMPLES,
        "{tag} {dir}: recovered length must be exactly N x {FRAME_SAMPLES} samples",
    );
    if loss {
        // The loss model must actually drop frames in THIS direction, or the
        // direction tests nothing.
        assert!(
            leg.concealed > 0,
            "{tag} {dir}: loss model dropped nothing ({} concealed) — not exercising concealment",
            leg.concealed,
        );
        assert_eq!(
            leg.delivered + leg.concealed,
            frames,
            "{tag} {dir}: delivered + concealed must account for every sequence",
        );
        // Graceful degradation: still correlated, just less than clean.
        assert!(
            leg.own_xcorr > 0.3,
            "{tag} {dir}: own correlation {:.3} collapsed — concealment not holding the stream together",
            leg.own_xcorr,
        );
    } else {
        assert_eq!(
            leg.delivered, frames,
            "{tag} {dir}: no datagram should drop"
        );
        assert_eq!(leg.concealed, 0, "{tag} {dir}: nothing to conceal");
        assert!(
            leg.own_xcorr > 0.8,
            "{tag} {dir}: own correlation {:.3} below 0.8 — codec/framing not recovering the signal",
            leg.own_xcorr,
        );
    }
    // Anti-cross-talk: the recovered stream must NOT reconstruct as the other
    // tone. Two distinct pure sines are near-orthogonal, so even the best lag
    // leaves the wrong-tone correlation low — and well below the own-tone one.
    assert!(
        leg.cross_xcorr < 0.2,
        "{tag} {dir}: cross-talk — recovered stream correlates {:.3} with the OTHER tone (>= 0.2)",
        leg.cross_xcorr,
    );
    assert!(
        leg.own_xcorr > leg.cross_xcorr + 0.3,
        "{tag} {dir}: own {:.3} not clearly above cross {:.3} — streams are being confused",
        leg.own_xcorr,
        leg.cross_xcorr,
    );
}

#[tokio::test]
async fn opus_full_duplex_two_concurrent_streams_over_one_iroh_link() {
    // 2 s of audio per direction: 100 frames. Enough that a 5 % loss model drops
    // several frames in EACH direction (a short run could drop zero and silently
    // become the clean run).
    const FRAMES: usize = 100;

    // --- clean link: the real gate. Distinct seeds per direction so the loss
    // patterns (when loss is on) differ; both large + nonzero (xorshift is
    // degenerate at state 0). ---
    let clean = run_duplex(FRAMES, 0.0, 0x9E37_79B9_7F4A_7C15, 0xD1B5_4A32_D192_ED03).await;
    report("clean", "A->B", &clean.a_to_b);
    report("clean", "B->A", &clean.b_to_a);
    assert_leg("clean", "A->B", &clean.a_to_b, FRAMES, false);
    assert_leg("clean", "B->A", &clean.b_to_a, FRAMES, false);

    // --- BLE-shaped link: 5 % loss per direction, must only degrade. ---
    let lossy = run_duplex(FRAMES, 0.05, 0x1234_5678_9ABC_DEF0, 0x0FED_CBA9_8765_4321).await;
    report("BLE-shaped", "A->B", &lossy.a_to_b);
    report("BLE-shaped", "B->A", &lossy.b_to_a);
    assert_leg("BLE-shaped", "A->B", &lossy.a_to_b, FRAMES, true);
    assert_leg("BLE-shaped", "B->A", &lossy.b_to_a, FRAMES, true);

    // Loss only degrades: neither lossy leg may out-correlate its clean twin.
    assert!(
        lossy.a_to_b.own_xcorr <= clean.a_to_b.own_xcorr + 1e-6,
        "BLE-shaped A->B correlation {:.3} should not exceed clean {:.3}",
        lossy.a_to_b.own_xcorr,
        clean.a_to_b.own_xcorr,
    );
    assert!(
        lossy.b_to_a.own_xcorr <= clean.b_to_a.own_xcorr + 1e-6,
        "BLE-shaped B->A correlation {:.3} should not exceed clean {:.3}",
        lossy.b_to_a.own_xcorr,
        clean.b_to_a.own_xcorr,
    );
}
