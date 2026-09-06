//! A test-only [`DatagramLink`] over plain UDP, so a harness can put a
//! userspace impairment proxy between two nodes and be *authoritative* about
//! the path.
//!
//! The iroh link is the wrong vehicle for simulating a flaky radio from the
//! outside: iroh exchanges address candidates and migrates the QUIC
//! connection onto the best path it finds, which is exactly the behaviour a
//! man-in-the-middle impairment proxy cannot survive — the connection walks
//! off the proxy and the "radio" stops mattering. n0's own answer is "make
//! the impaired path the only transport"; this applies that at our seam
//! instead, where [`DatagramLink`] is already the pluggable boundary the BLE
//! backend injects through.
//!
//! Wire format: 32 raw bytes of the sender's node id, then the CoAP datagram
//! verbatim. Self-describing, so the receive side needs no reverse routing
//! table and the impairment proxy needs no protocol knowledge at all.
//!
//! Not for production meshes: no encryption, no authentication beyond the
//! asserted sender id. The CoAP payloads it carries are federation blocks
//! whose *contents* are already signed and end-to-end encrypted, and the sim
//! runs on loopback — but nothing here verifies the 32-byte header. That is
//! acceptable for a fault-injection harness and for nothing else, which is
//! why it only exists behind an explicit opt-in flag.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use neutrino_main::{DatagramLink, LinkAddr};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, mpsc};

/// 32-byte node id, the same shape the iroh link keys peers by.
type NodeKey = [u8; 32];

fn hex32(bytes: &NodeKey) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn unhex32(addr: &[u8]) -> std::io::Result<NodeKey> {
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    }
    if addr.len() != 64 {
        return Err(std::io::Error::other("sim link: address must be 64 hex"));
    }
    let mut key = [0u8; 32];
    for (byte, pair) in key.iter_mut().zip(addr.chunks_exact(2)) {
        let (Some(hi), Some(lo)) = (nibble(pair[0]), nibble(pair[1])) else {
            return Err(std::io::Error::other("sim link: bad hex in address"));
        };
        *byte = (hi << 4) | lo;
    }
    Ok(key)
}

pub(crate) struct SimUdpLink {
    socket: Arc<UdpSocket>,
    our_id: NodeKey,
    /// Where to send a peer's datagrams — in a harness, the impairment
    /// proxy's address, not the peer's own.
    peers: HashMap<NodeKey, SocketAddr>,
    inbound: AsyncMutex<mpsc::Receiver<(LinkAddr, Vec<u8>)>>,
}

impl SimUdpLink {
    pub(crate) async fn bind(
        our_id: NodeKey,
        bind: SocketAddr,
        peers: Vec<(NodeKey, SocketAddr)>,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        let (tx, rx) = mpsc::channel(256);
        let reader = socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let Ok((n, _from)) = reader.recv_from(&mut buf).await else {
                    break;
                };
                if n < 32 {
                    continue;
                }
                let mut sender = [0u8; 32];
                sender.copy_from_slice(&buf[..32]);
                let src: LinkAddr = hex32(&sender).into_bytes();
                // Best-effort like every link here: drop rather than block.
                let _ = tx.try_send((src, buf[32..n].to_vec()));
            }
        });
        tracing::warn!(
            bind = %bind,
            peers = peers.len(),
            "SIM LINK ACTIVE: plain-UDP test transport, not a production medium"
        );
        Ok(Arc::new(Self {
            socket,
            our_id,
            peers: peers.into_iter().collect(),
            inbound: AsyncMutex::new(rx),
        }))
    }
}

#[async_trait::async_trait]
impl DatagramLink for SimUdpLink {
    async fn send(&self, dst: &[u8], datagram: &[u8]) -> std::io::Result<()> {
        let key = unhex32(dst)?;
        let Some(addr) = self.peers.get(&key) else {
            return Err(std::io::Error::other("sim link: unknown peer"));
        };
        let mut frame = Vec::with_capacity(32 + datagram.len());
        frame.extend_from_slice(&self.our_id);
        frame.extend_from_slice(datagram);
        self.socket.send_to(&frame, addr).await.map(|_| ())
    }

    async fn recv(&self) -> Option<(LinkAddr, Vec<u8>)> {
        self.inbound.lock().await.recv().await
    }
}
