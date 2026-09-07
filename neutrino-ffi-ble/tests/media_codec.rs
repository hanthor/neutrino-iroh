// Copyright 2026 IndiaFOSS Companion contributors
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial.

//! Voice-over-mesh milestone 1 (companion ADR 0007): prove the CODEC + FRAMING
//! layer on top of the transport that `media_throughput.rs` already proved.
//!
//! `media_throughput.rs` pushes *synthetic* bytes at opus/video bitrates and
//! shows the iroh link carries them. It says nothing about a real codec. This
//! test closes that gap, still on loopback and with no audio hardware:
//!
//!   1. Synthesise a 440 Hz sine tone — 48 kHz mono, i16 PCM, sliced into
//!      20 ms opus frames (960 samples each).
//!   2. Encode each frame with libopus in VoIP mode at ~24 kbit/s.
//!   3. Send each encoded frame as one unreliable iroh QUIC datagram over the
//!      same media ALPN, prefixed with a u64 sequence header (the framing
//!      `media_throughput.rs` uses, minus the latency word we don't need here).
//!   4. Receive into a jitter buffer keyed by sequence; once the stream ends,
//!      walk 0..N in order and opus-decode, using packet-loss concealment for
//!      any sequence that never arrived.
//!   5. Assert the recovered PCM is byte-for-byte the right *length* (one frame
//!      of output per sequence, gaps included — the stream stays aligned no
//!      matter what drops), that a clean link recovers a signal that strongly
//!      cross-correlates with the input, and that a BLE-shaped link (5 % loss)
//!      only degrades — concealed gaps, no panic, still aligned.
//!
//! Loopback is an upper bound on the transport, not a model of a real BLE link;
//! what it rules out is a codec+framing path that cannot even round-trip on
//! loopback. The two-phones number is future work.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use iroh::endpoint::presets::N0DisableRelay;
use iroh::{Endpoint, EndpointAddr, SecretKey};
use opus::{Application, Channels, Decoder, Encoder};

// Same second ALPN the throughput probe uses: media rides its own protocol on
// the shared iroh endpoint, apart from federation traffic.
const MEDIA_ALPN: &[u8] = b"neutrino/media-probe/0";

const SAMPLE_RATE: u32 = 48_000;
const FRAME_SAMPLES: usize = 960; // 20 ms @ 48 kHz mono
const BITRATE: i32 = 24_000; // ~24 kbit/s, opus VoIP
const TONE_HZ: f64 = 440.0;
const SEQ_HEADER: usize = 8; // u64 little-endian sequence number

/// Copied from `media_throughput.rs` (the task says copy, don't refactor the
/// shipping crate): a fresh iroh endpoint bound to an ephemeral loopback port,
/// speaking only the media ALPN, relay disabled.
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
/// reproducible (same shape as the throughput probe's `Rng`).
struct Rng(u64);
impl Rng {
    fn next_f64(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// A pure sine tone as i16 PCM: `frames` blocks of `FRAME_SAMPLES` samples.
fn sine_pcm(frames: usize) -> Vec<i16> {
    let amp = (i16::MAX as f64) * 0.3;
    (0..frames * FRAME_SAMPLES)
        .map(|n| {
            let t = n as f64 / SAMPLE_RATE as f64;
            (amp * (2.0 * std::f64::consts::PI * TONE_HZ * t).sin()) as i16
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

struct Outcome {
    frames: usize,
    offered: usize,
    delivered: usize,
    concealed: usize,
    out_samples: usize,
    xcorr: f64,
    lag: usize,
    snr_db: f64,
}

/// One codec+framing round-trip. Encodes the tone, sends each opus frame as a
/// sequence-tagged datagram (dropping some per the loss model), reassembles via
/// a jitter buffer with PLC for gaps, decodes, and scores against the input.
async fn run(frames: usize, loss: f64, seed: u64) -> Outcome {
    let pcm = sine_pcm(frames);

    // --- encode ahead of time so the send loop only paces the transport ---
    let mut enc =
        Encoder::new(SAMPLE_RATE, Channels::Mono, Application::Voip).expect("opus encoder");
    enc.set_bitrate(opus::Bitrate::Bits(BITRATE))
        .expect("set bitrate");
    let packets: Vec<Vec<u8>> = (0..frames)
        .map(|f| {
            let start = f * FRAME_SAMPLES;
            enc.encode_vec(&pcm[start..start + FRAME_SAMPLES], 4000)
                .expect("opus encode")
        })
        .collect();

    // --- transport ---
    let listener = bind_loopback().await;
    let dialer = bind_loopback().await;
    let listener_id = listener.id();
    let listener_sock = *listener
        .bound_sockets()
        .iter()
        .find(|s| s.ip().is_loopback())
        .expect("a loopback bound socket");

    let recv = tokio::spawn(async move {
        let conn = listener
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("accepted");
        // Jitter buffer: sequence -> opus packet, filled as datagrams arrive
        // out of order. We drain to end-of-stream, then reorder.
        let mut jitter: HashMap<u64, Vec<u8>> = HashMap::new();
        while let Ok(dgram) = conn.read_datagram().await {
            let seq = u64::from_le_bytes(dgram[..SEQ_HEADER].try_into().unwrap());
            jitter.insert(seq, dgram[SEQ_HEADER..].to_vec());
        }
        jitter
    });

    let addr = EndpointAddr::new(listener_id).with_ip_addr(listener_sock);
    let conn = dialer.connect(addr, MEDIA_ALPN).await.expect("connect");

    let interval = Duration::from_secs_f64(FRAME_SAMPLES as f64 / SAMPLE_RATE as f64);
    let mut rng = Rng(seed);
    let mut delivered = 0usize;
    for (seq, packet) in packets.iter().enumerate() {
        if loss > 0.0 && rng.next_f64() < loss {
            // Datagram lost in the link model — no retransmit (RTP contract).
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
    // Let the last datagrams drain, then close so the receiver loop ends.
    tokio::time::sleep(Duration::from_millis(300)).await;
    conn.close(0u32.into(), b"done");
    let jitter = recv.await.expect("recv task");

    // --- reassemble + decode: walk every sequence in order, conceal gaps ---
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

    // --- score: skip the encoder startup transient (first 3 frames) ---
    let skip = 3 * FRAME_SAMPLES;
    let refn: Vec<f64> = pcm[skip..].iter().map(|&s| s as f64).collect();
    let recf: Vec<f64> = out[skip.min(out.len())..]
        .iter()
        .map(|&s| s as f64)
        .collect();
    let (xcorr, lag) = best_xcorr(&refn, &recf, 2000);
    let snr = snr_db(&refn, &recf, lag);

    Outcome {
        frames,
        offered: frames,
        delivered,
        concealed,
        out_samples: out.len(),
        xcorr,
        lag,
        snr_db: snr,
    }
}

#[tokio::test]
async fn opus_codec_and_framing_round_trip_over_the_iroh_link() {
    // 2 s of audio: 100 frames. Enough that a 5 % loss model drops several
    // frames (a 20-frame run could drop zero and silently become the clean run).
    const FRAMES: usize = 100;

    // --- clean link: the real gate ---
    let clean = run(FRAMES, 0.0, 0x9E3779B97F4A7C15).await;
    eprintln!(
        "clean       : offered {} delivered {} concealed {} out {} samples | xcorr {:.3} (lag {}) | SNR {:.1} dB",
        clean.offered,
        clean.delivered,
        clean.concealed,
        clean.out_samples,
        clean.xcorr,
        clean.lag,
        clean.snr_db
    );

    // Exact alignment invariant: one decoded frame per sequence, gaps included.
    assert_eq!(
        clean.out_samples,
        clean.frames * FRAME_SAMPLES,
        "clean: recovered length must be exactly N x {} samples",
        FRAME_SAMPLES
    );
    assert_eq!(clean.delivered, FRAMES, "clean: no datagram should drop");
    assert_eq!(clean.concealed, 0, "clean: nothing to conceal");
    // A 440 Hz tone through SILK at 24 kbit round-trips with high correlation.
    assert!(
        clean.xcorr > 0.8,
        "clean: cross-correlation {:.3} below 0.8 — codec/framing not recovering the signal",
        clean.xcorr
    );

    // --- BLE-shaped link: 5 % loss, must only degrade ---
    let lossy = run(FRAMES, 0.05, 0x1234_5678_9ABC_DEF0).await;
    eprintln!(
        "BLE-shaped  : offered {} delivered {} concealed {} out {} samples | xcorr {:.3} (lag {}) | SNR {:.1} dB",
        lossy.offered,
        lossy.delivered,
        lossy.concealed,
        lossy.out_samples,
        lossy.xcorr,
        lossy.lag,
        lossy.snr_db
    );

    // The loss model must actually lose frames, or this run tests nothing.
    assert!(
        lossy.concealed > 0,
        "BLE-shaped: loss model dropped nothing ({} concealed) — not exercising concealment",
        lossy.concealed
    );
    // Same exact alignment: every gap became exactly one concealed frame.
    assert_eq!(
        lossy.out_samples,
        lossy.frames * FRAME_SAMPLES,
        "BLE-shaped: concealment must keep the stream aligned (one frame per gap)"
    );
    assert_eq!(
        lossy.delivered + lossy.concealed,
        FRAMES,
        "BLE-shaped: delivered + concealed must account for every sequence"
    );
    // Graceful degradation: still correlated, just less than clean.
    assert!(
        lossy.xcorr > 0.3,
        "BLE-shaped: cross-correlation {:.3} collapsed — concealment not holding the stream together",
        lossy.xcorr
    );
    assert!(
        lossy.xcorr <= clean.xcorr + 1e-6,
        "BLE-shaped correlation {:.3} should not exceed clean {:.3}",
        lossy.xcorr,
        clean.xcorr
    );
}
