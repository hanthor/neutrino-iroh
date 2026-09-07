// Copyright 2026 IndiaFOSS Companion contributors
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial.

//! Voice/video-over-mesh spike (companion ADR 0007): can the iroh link that
//! carries federation also carry real-time media?
//!
//! The plan is a second ALPN on the same iroh endpoint — inheriting the
//! GATT->L2CAP-CoC upgrade, QUIC congestion control, and node addressing the
//! federation link already has — with media as unreliable QUIC datagrams
//! (the RTP contract: a late frame is worthless, so drop beats retransmit).
//! Before building audio capture and the ALPN wiring, this measures whether
//! the transport itself sustains media bitrates with usable latency and loss,
//! which is the load-bearing unknown. It runs iroh only — no neutrino, no
//! Bluetooth — over loopback, so it is an upper bound on the transport, not a
//! model of a real BLE link (that number needs the two phones). What it rules
//! *out* is a transport that cannot even keep up on loopback.
//!
//! Two profiles, one frame per packet at the codec's frame rate:
//!   - opus voice: 32 kbit/s, 20 ms frames  (~80 B/frame, 50 fps)
//!   - low-res video: 300 kbit/s, 30 fps     (~1250 B/frame)
//!
//! Each carries a u64 send-nanos header so the receiver measures one-way
//! latency and, via a sequence number, loss.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use iroh::endpoint::presets::N0DisableRelay;
use iroh::{Endpoint, EndpointAddr, SecretKey};

const MEDIA_ALPN: &[u8] = b"neutrino/media-probe/0";

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

struct Profile {
    name: &'static str,
    frame_bytes: usize,
    fps: u32,
    seconds: u32,
    /// Fraction of datagrams the model drops (0.0 = clean loopback).
    loss: f64,
    /// Extra one-way latency the model adds before each send, ms.
    extra_latency_ms: u64,
}

/// A tiny deterministic PRNG (xorshift) so the loss pattern is reproducible
/// without pulling in a dependency; seeded per profile.
struct Rng(u64);
impl Rng {
    fn next_f64(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

struct Report {
    sent: u64,
    received: u64,
    dropped_by_model: u64,
    goodput_kbit: f64,
    mean_latency_ms: f64,
    max_latency_ms: f64,
}

/// One-way media stream: dialer sends `fps * seconds` datagrams paced at the
/// frame interval; listener records arrival for goodput, loss, and latency.
async fn run(profile: &Profile) -> Report {
    let listener = bind_loopback().await;
    let dialer = bind_loopback().await;
    let listener_id = listener.id();
    let listener_sock = *listener
        .bound_sockets()
        .iter()
        .find(|s| s.ip().is_loopback())
        .expect("a loopback bound socket");

    let total = (profile.fps * profile.seconds) as u64;
    let recv = tokio::spawn(async move {
        let conn = listener
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("accepted");
        let mut received = 0u64;
        let mut latency_sum = Duration::ZERO;
        let mut latency_max = Duration::ZERO;
        let mut bytes = 0u64;
        // Stop when the sender's connection closes (all frames flushed or a
        // read error once it drops).
        while let Ok(dgram) = conn.read_datagram().await {
            received += 1;
            bytes += dgram.len() as u64;
            // Header: send-nanos since a shared epoch. We do not share a clock
            // across endpoints, but both run in this process, so Instant is
            // comparable via a captured base passed through the payload's first
            // 8 bytes as elapsed-since-start on the SENDER; the receiver
            // compares against its own elapsed-since-the-same-start. Close
            // enough for a relative latency signal on loopback.
            let sent_ns = u64::from_le_bytes(dgram[..8].try_into().unwrap());
            let now_ns = START.get().copied().unwrap().elapsed().as_nanos() as u64;
            let latency = Duration::from_nanos(now_ns.saturating_sub(sent_ns));
            latency_sum += latency;
            latency_max = latency_max.max(latency);
        }
        (received, bytes, latency_sum, latency_max)
    });

    let addr = EndpointAddr::new(listener_id).with_ip_addr(listener_sock);
    let conn = dialer.connect(addr, MEDIA_ALPN).await.expect("connect");

    // The path's max datagram size bounds one packet; a codec frame larger than
    // that is sliced across several, as RTP fragments over UDP. 16 bytes of
    // that budget is our header (elapsed-ns + seq).
    let max_dgram = conn.max_datagram_size().unwrap_or(1200).max(64);
    let slice_payload = max_dgram - 16;
    eprintln!("  ({}: path max datagram {} B)", profile.name, max_dgram);

    let interval = Duration::from_secs_f64(1.0 / profile.fps as f64);
    let start = Instant::now();
    let mut sent = 0u64;
    let mut dropped_by_model = 0u64;
    let mut rng = Rng(0x9E3779B97F4A7C15 ^ profile.name.len() as u64);
    for seq in 0..total {
        let mut remaining = profile.frame_bytes;
        while remaining > 0 {
            let chunk = remaining.min(slice_payload);
            // Link model: drop this datagram, or hold it back to model latency.
            if profile.loss > 0.0 && rng.next_f64() < profile.loss {
                dropped_by_model += 1;
                remaining -= chunk;
                continue;
            }
            if profile.extra_latency_ms > 0 {
                tokio::time::sleep(Duration::from_millis(profile.extra_latency_ms)).await;
            }
            let mut buf = BytesMut::with_capacity(chunk + 16);
            let elapsed_ns = START.get().copied().unwrap().elapsed().as_nanos() as u64;
            buf.put_u64_le(elapsed_ns);
            buf.put_u64_le(seq);
            buf.resize(chunk + 16, 0);
            if conn.send_datagram(Bytes::from(buf)).is_ok() {
                sent += 1;
            }
            remaining -= chunk;
        }
        let next = start + interval * (seq as u32 + 1);
        tokio::time::sleep_until(next.into()).await;
    }
    // Let the last frames drain, then close so the receiver loop ends.
    tokio::time::sleep(Duration::from_millis(300)).await;
    conn.close(0u32.into(), b"done");

    let (received, bytes, latency_sum, latency_max) = recv.await.expect("recv task");
    let secs = profile.seconds as f64;
    Report {
        sent,
        received,
        dropped_by_model,
        goodput_kbit: (bytes as f64 * 8.0) / secs / 1000.0,
        mean_latency_ms: if received > 0 {
            latency_sum.as_secs_f64() * 1000.0 / received as f64
        } else {
            0.0
        },
        max_latency_ms: latency_max.as_secs_f64() * 1000.0,
    }
}

use std::sync::OnceLock;
static START: OnceLock<Instant> = OnceLock::new();

#[tokio::test]
async fn media_bitrates_sustain_over_the_iroh_link() {
    START.set(Instant::now()).ok();
    let profiles = [
        // Clean loopback: proves the software transport keeps up (must pass).
        Profile {
            name: "opus-voice-32kbit clean",
            frame_bytes: 80,
            fps: 50,
            seconds: 3,
            loss: 0.0,
            extra_latency_ms: 0,
        },
        Profile {
            name: "low-res-video-300kbit clean",
            frame_bytes: 1250,
            fps: 30,
            seconds: 3,
            loss: 0.0,
            extra_latency_ms: 0,
        },
        // BLE-shaped: 5% loss, ~40ms added one-way latency. Reports how a
        // best-effort media stream degrades — a resilience signal for the
        // jitter buffer + opus PLC to absorb, not a hard gate.
        Profile {
            name: "opus-voice-32kbit BLE-shaped",
            frame_bytes: 80,
            fps: 50,
            seconds: 3,
            loss: 0.05,
            extra_latency_ms: 40,
        },
        Profile {
            name: "low-res-video-300kbit BLE-shaped",
            frame_bytes: 1250,
            fps: 30,
            seconds: 3,
            loss: 0.05,
            extra_latency_ms: 40,
        },
    ];
    for p in &profiles {
        let r = run(p).await;
        let loss = if r.sent + (r.dropped_by_model) > 0 {
            (r.dropped_by_model) as f64 * 100.0 / (r.sent + r.dropped_by_model) as f64
        } else {
            0.0
        };
        eprintln!(
            "{}: offered {} sent {} recv {} model-loss {:.1}% goodput {:.0} kbit/s latency mean {:.1}ms max {:.1}ms",
            p.name,
            (p.frame_bytes * p.fps as usize) as f64 * 8.0 / 1000.0,
            r.sent,
            r.received,
            loss,
            r.goodput_kbit,
            r.mean_latency_ms,
            r.max_latency_ms
        );
        if p.loss == 0.0 {
            // Clean rows are the real gate: the transport must keep up.
            let transport_loss = if r.sent > 0 {
                (r.sent.saturating_sub(r.received)) as f64 * 100.0 / r.sent as f64
            } else {
                100.0
            };
            assert!(
                transport_loss < 2.0,
                "{}: transport loss {:.1}% too high",
                p.name,
                transport_loss
            );
            let offered = (p.frame_bytes * p.fps as usize) as f64 * 8.0 / 1000.0;
            assert!(
                r.goodput_kbit > offered * 0.9,
                "{}: goodput {:.0} kbit/s far below offered {:.0}",
                p.name,
                r.goodput_kbit,
                offered
            );
        } else {
            // Shaped rows: what actually arrives should track (1 - loss). This
            // is a sanity bound on the model, not a transport gate.
            assert!(
                r.received as f64 >= r.sent as f64 * 0.95,
                "{}: transport dropped beyond the model ({} sent, {} recv)",
                p.name,
                r.sent,
                r.received
            );
        }
    }
}
