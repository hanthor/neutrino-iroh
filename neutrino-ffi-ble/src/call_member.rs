// Copyright 2026 IndiaFOSS Companion contributors
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial.

//! MatrixRTC call membership for a mesh/iroh focus — the signalling model of
//! companion ADR 0007 ("reuse the membership layer verbatim, extend the focus
//! layer"), issue #13.
//!
//! Pure data: this module builds and parses the *content* of an
//! `org.matrix.msc3401.call.member` state event and derives its state key. It
//! sends nothing. Publishing is `PUT /state/{type}/{state_key}` on the room
//! through the embedded homeserver (which federates it as an ordinary state
//! event); reading is enumerating the room's `call.member` state. Both are the
//! caller's, so this stays testable without a homeserver.
//!
//! # What it conforms to, and where
//!
//! MatrixRTC is MSC4143 ("MatrixRTC", matrix-org/matrix-spec-proposals#4143).
//! Its *current* draft text (the `toger5/matrixRTC` branch, 2026-07) has moved
//! on to `m.rtc.slot` / `m.rtc.member` sticky events — a shape nothing ships
//! yet. What Element Call, matrix-js-sdk, ruma and Element X speak today is the
//! earlier MSC4143 revision, which matrix-js-sdk documents as
//!
//! > the *OLD* form of MSC4143, which uses state events to store membership
//! > (`src/matrixrtc/membershipData/session.ts`, `SessionMembershipData`)
//!
//! and ruma implements as `CallMemberEventContent::SessionContent`
//! (`ruma-events/src/call/member/member_data.rs`, `SessionMembershipData`).
//! That is the wire shape this module produces, field for field:
//!
//! | field            | meaning (per the js-sdk / ruma docs)                           |
//! |------------------|----------------------------------------------------------------|
//! | `application`    | session type; `"m.call"` for a call                            |
//! | `call_id`        | `""` for the room-scoped call (immune to creation races)       |
//! | `scope`          | `"m.room"`: the one call every member may join                 |
//! | `device_id`      | one membership per device                                      |
//! | `foci_preferred` | foci this member offers, each `{ "type": ..., ...}`            |
//! | `focus_active`   | `{ "type": ... }` — how this member is currently connected     |
//! | `created_ts`     | optional; `origin_server_ts` of the initial join, on updates   |
//! | `expires`        | optional ms delta from the join after which the member is stale|
//!
//! The event *type* keeps the unstable MSC3401 prefix — MSC3401 §"Unstable
//! prefix" maps `m.call.member` → `org.matrix.msc3401.call.member`, and MSC4143
//! reused that type rather than mint one — even though the *content* is the
//! MSC4143 session shape, not MSC3401's `m.calls[]` array. The state key is per
//! device, `_{user_id}_{device_id}_m.call` (matrix-js-sdk
//! `MembershipManager.makeMembershipStateKey`: `${user}_${device}_${application}${slot}`,
//! slot `""` for the room call, underscore-prefixed outside MSC3757 rooms so
//! only the sender may write it; ruma `CallMemberStateKey`'s
//! `UnderscoreMemberId` form). Join = non-empty content; leave = `{}`
//! (optionally `{ "leave_reason": ... }`, ruma `EmptyMembershipData`).
//!
//! # Where it deliberately leaves the beaten path
//!
//! The implemented model knows exactly one focus `type`, `livekit` (MSC4195),
//! and no peer-to-peer type. A mesh call has no SFU, so we define the focus
//! type [`MESH_FOCUS_TYPE`] = `in.indiafoss.mesh.iroh`, whose content is what
//! a LiveKit focus's `livekit_service_url` + JWT stand in for: the peer's iroh
//! node id and its opus parameters, carried in the membership state itself. A
//! peer reads the other's `node_id` and dials it on the media ALPN
//! (`relay_transport::MEDIA_ALPN`). ADR 0007 option (a), "honest extension":
//! a strict ruma client (Element X) fails the untagged `SessionContent` arm on
//! the unknown focus type and reads such a member as left; a lenient
//! matrix-js-sdk client still lists it. Accepted — only this medium can
//! connect the media anyway.
//!
//! Foreign members are parsed, not rejected: a `livekit` focus deserializes
//! (as [`Focus::Livekit`]) so a room's call state enumerates cleanly, and
//! [`mesh_members`] simply yields no mesh focus for it. Any *other* focus type
//! is a parse error (not silently "left"): unlike ruma, [`CallMemberContent`]'s
//! leave arm rejects unknown fields, so garbage never masquerades as a hang-up.

use serde::{Deserialize, Serialize};

/// The state event type: MSC3401's unstable prefix for `m.call.member`,
/// reused by MSC4143 for the session-membership content.
pub const CALL_MEMBER_EVENT_TYPE: &str = "org.matrix.msc3401.call.member";

/// Focus `type` for a mesh/iroh call: no SFU, the peer IS the focus.
pub const MESH_FOCUS_TYPE: &str = "in.indiafoss.mesh.iroh";

/// The MatrixRTC application for a call (`Application::Call` in ruma).
pub const APPLICATION_CALL: &str = "m.call";

/// The room-scoped call: one per room, any member may join (`CallScope::Room`).
pub const SCOPE_ROOM: &str = "m.room";

/// `call_id` of the room-scoped call — the empty string, by convention.
pub const ROOM_CALL_ID: &str = "";

/// Opus parameters a mesh peer advertises for its receive side. Defaults are
/// what the loopback probes established (48 kHz mono, 20 ms frames,
/// ~24 kbit/s VoIP) — the shape a call over the BLE budget needs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpusParams {
    /// Target bitrate, bits per second.
    pub bitrate: u32,
    /// Sample rate, Hz. Opus is 48 kHz internally; this is the PCM rate at the
    /// codec boundary.
    #[serde(default = "default_sample_rate")]
    pub sample_rate: u32,
    /// Frame duration, milliseconds (one datagram per frame).
    #[serde(default = "default_frame_ms")]
    pub frame_ms: u32,
    /// Channel count; the mesh is mono.
    #[serde(default = "default_channels")]
    pub channels: u8,
}

fn default_sample_rate() -> u32 {
    48_000
}
fn default_frame_ms() -> u32 {
    20
}
fn default_channels() -> u8 {
    1
}

impl Default for OpusParams {
    fn default() -> Self {
        Self {
            bitrate: 24_000,
            sample_rate: default_sample_rate(),
            frame_ms: default_frame_ms(),
            channels: default_channels(),
        }
    }
}

/// The `media` object of a mesh focus: which audio codec and how.
///
/// `audio` is the codec name and is always `"opus"` here; it is a field rather
/// than implied so a future codec (or a `video` sibling, ADR 0007 milestone 4)
/// is an additive change to the same object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshMedia {
    /// Audio codec name. Only `"opus"` is defined.
    pub audio: String,
    /// The opus parameters, flattened next to `audio`.
    #[serde(flatten)]
    pub opus: OpusParams,
}

impl MeshMedia {
    /// Opus with the given parameters.
    pub fn opus(opus: OpusParams) -> Self {
        Self {
            audio: "opus".into(),
            opus,
        }
    }
}

/// A mesh/iroh focus: the member's own iroh node id plus its media parameters.
/// This is the whole negotiation — no SFU URL, no token service, no SDP leg.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshFocus {
    /// The member's iroh node id, lowercase 64-hex (its federation
    /// `server_name`), which the peer dials on the media ALPN.
    pub node_id: String,
    /// Codec and parameters this member receives.
    pub media: MeshMedia,
}

impl MeshFocus {
    /// Build a focus for the given raw node id and opus parameters.
    pub fn new(node_id: &[u8; 32], opus: OpusParams) -> Self {
        Self {
            node_id: hex32(node_id),
            media: MeshMedia::opus(opus),
        }
    }

    /// The node id as raw bytes, if the string is a canonical 64-hex id.
    pub fn node_key(&self) -> Option<[u8; 32]> {
        unhex32(&self.node_id)
    }
}

/// One entry of `foci_preferred`, tagged by `type`.
///
/// `livekit` is included so members advertised by LiveKit clients parse (with
/// ruma's field names) instead of failing the whole state read; we never
/// produce it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Focus {
    /// A mesh/iroh peer (this medium).
    #[serde(rename = "in.indiafoss.mesh.iroh")]
    MeshIroh(MeshFocus),
    /// A LiveKit SFU (MSC4195); parsed for tolerance only.
    #[serde(rename = "livekit")]
    Livekit {
        /// The room alias on the SFU.
        livekit_alias: String,
        /// The JWT service URL.
        livekit_service_url: String,
    },
}

/// `focus_active`: how this member is currently connected, tagged by `type`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ActiveFocus {
    /// Connected over the mesh: the node id in `foci_preferred` is the leg.
    #[serde(rename = "in.indiafoss.mesh.iroh")]
    MeshIroh,
    /// Connected through a LiveKit SFU (`focus_selection` per MSC4195).
    #[serde(rename = "livekit")]
    Livekit {
        /// How the SFU was chosen; `oldest_membership` in practice.
        focus_selection: String,
    },
}

/// The non-empty content of a `call.member` state event: one device's
/// membership in a session (`SessionMembershipData`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMembership {
    /// Session type; [`APPLICATION_CALL`] for a call.
    pub application: String,
    /// [`ROOM_CALL_ID`] for the room-scoped call.
    pub call_id: String,
    /// [`SCOPE_ROOM`]; who owns the call. Optional on the wire (js-sdk), but
    /// always written here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The member's Matrix device id.
    pub device_id: String,
    /// Foci this member offers; for a mesh member, exactly one
    /// [`Focus::MeshIroh`].
    #[serde(default)]
    pub foci_preferred: Vec<Focus>,
    /// The focus in use.
    pub focus_active: ActiveFocus,
    /// `origin_server_ts` of the initial join, carried on updates; absent on
    /// the join itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_ts: Option<u64>,
    /// Milliseconds after the join at which this membership is stale. The
    /// dead-man's switch when the leave event never arrives (MSC4140 delayed
    /// events are the primary mechanism; this is the fallback our embedded
    /// homeserver can honour without them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
}

/// The empty content that means "left" — `{}`, or `{ "leave_reason": ... }`
/// (ruma `EmptyMembershipData`; `m.lost_connection` when a delayed event
/// fired). Unknown fields are rejected so a malformed session is an error,
/// never a silent hang-up.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeftMembership {
    /// Why the member left, if not an ordinary hang-up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leave_reason: Option<String>,
}

/// Content of an `org.matrix.msc3401.call.member` state event: a joined
/// session, or the empty content of a member who left.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CallMemberContent {
    /// In the call.
    Session(SessionMembership),
    /// Not (or no longer) in the call.
    Left(LeftMembership),
}

impl CallMemberContent {
    /// Content to *join* the room-scoped call from `device_id`, advertising
    /// this node as a mesh focus. `expires` is the staleness delta in ms
    /// (`None` to rely solely on delayed-event cleanup).
    pub fn join(
        node_id: &[u8; 32],
        device_id: impl Into<String>,
        opus: OpusParams,
        expires_ms: Option<u64>,
    ) -> Self {
        Self::Session(SessionMembership {
            application: APPLICATION_CALL.into(),
            call_id: ROOM_CALL_ID.into(),
            scope: Some(SCOPE_ROOM.into()),
            device_id: device_id.into(),
            foci_preferred: vec![Focus::MeshIroh(MeshFocus::new(node_id, opus))],
            focus_active: ActiveFocus::MeshIroh,
            created_ts: None,
            expires: expires_ms,
        })
    }

    /// Content to *leave*: `{}`.
    pub fn leave() -> Self {
        Self::Left(LeftMembership::default())
    }

    /// Serialize to the event-content JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("call.member content is plain data")
    }

    /// Parse event-content JSON.
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// The joined session, if any.
    pub fn session(&self) -> Option<&SessionMembership> {
        match self {
            Self::Session(s) => Some(s),
            Self::Left(_) => None,
        }
    }
}

impl SessionMembership {
    /// The mesh focus this member offers, if it is a mesh member.
    pub fn mesh_focus(&self) -> Option<&MeshFocus> {
        self.foci_preferred.iter().find_map(|f| match f {
            Focus::MeshIroh(m) => Some(m),
            Focus::Livekit { .. } => None,
        })
    }

    /// Whether this membership is stale at `now_ms`, given the event's
    /// `origin_server_ts`. Joined-at is `min(created_ts, origin_server_ts)`
    /// (ruma's rule); no `expires` means never stale by time (the leave event,
    /// or a delayed event, is then the only end).
    pub fn is_expired(&self, origin_server_ts_ms: u64, now_ms: u64) -> bool {
        let Some(expires) = self.expires else {
            return false;
        };
        let joined = self
            .created_ts
            .map_or(origin_server_ts_ms, |c| c.min(origin_server_ts_ms));
        now_ms >= joined.saturating_add(expires)
    }
}

/// The per-device state key for the room call: `_{user_id}_{device_id}_m.call`.
///
/// Leading underscore: outside MSC3757 rooms a state key beginning with the
/// sender's user id is the *only* form other users cannot overwrite, and the
/// `_` prefix is how js-sdk/ruma mark the per-device variant. `m.call` is the
/// application; the room call's slot id is `""`, so nothing follows it.
pub fn state_key(user_id: &str, device_id: &str) -> String {
    format!("_{user_id}_{device_id}_{APPLICATION_CALL}")
}

/// One mesh peer currently in the call, as read from room state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshMember {
    /// The event's state key (identifies user + device).
    pub state_key: String,
    /// The member's node id, raw.
    pub node_id: [u8; 32],
    /// The member's opus parameters (what it wants to receive).
    pub opus: OpusParams,
    /// The member's device id.
    pub device_id: String,
}

/// Enumerate the mesh members of the room call from its `call.member` state:
/// every `(state_key, origin_server_ts, content)` whose content is a joined
/// `m.call` session with a parseable mesh focus and that has not expired at
/// `now_ms`. Left members, LiveKit-only members, other applications and
/// unparseable node ids are skipped, not errors — this is the read side of
/// "who can I dial".
pub fn mesh_members<'a>(
    state: impl IntoIterator<Item = (&'a str, u64, &'a CallMemberContent)>,
    now_ms: u64,
) -> Vec<MeshMember> {
    state
        .into_iter()
        .filter_map(|(key, origin_ts, content)| {
            let s = content.session()?;
            if s.application != APPLICATION_CALL || s.is_expired(origin_ts, now_ms) {
                return None;
            }
            let focus = s.mesh_focus()?;
            Some(MeshMember {
                state_key: key.to_string(),
                node_id: focus.node_key()?,
                opus: focus.media.opus.clone(),
                device_id: s.device_id.clone(),
            })
        })
        .collect()
}

/// Lowercase-hex a 32-byte node id (same rendering as the transport's
/// `server_name`; duplicated rather than shared so this module stays free of
/// the transport).
fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Strict inverse of [`hex32`]: exactly 64 lowercase hex chars.
fn unhex32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut key = [0u8; 32];
    for (out, pair) in key.iter_mut().zip(bytes.as_chunks::<2>().0) {
        *out = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn node() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        k
    }

    #[test]
    fn join_content_has_the_msc4143_session_shape_with_a_mesh_focus() {
        let content =
            CallMemberContent::join(&node(), "DEVICEID", OpusParams::default(), Some(3_600_000));
        let v: Value = serde_json::from_str(&content.to_json()).unwrap();
        // The ADR 0007 sample, field for field.
        assert_eq!(
            v,
            json!({
                "application": "m.call",
                "call_id": "",
                "scope": "m.room",
                "device_id": "DEVICEID",
                "foci_preferred": [{
                    "type": "in.indiafoss.mesh.iroh",
                    "node_id": hex32(&node()),
                    "media": {
                        "audio": "opus",
                        "bitrate": 24000,
                        "sample_rate": 48000,
                        "frame_ms": 20,
                        "channels": 1
                    }
                }],
                "focus_active": { "type": "in.indiafoss.mesh.iroh" },
                "expires": 3_600_000
            })
        );
        // Never the LiveKit keys.
        assert!(!content.to_json().contains("livekit"));
    }

    #[test]
    fn join_round_trips_through_json() {
        let content = CallMemberContent::join(
            &node(),
            "DEVICEID",
            OpusParams {
                bitrate: 16_000,
                ..Default::default()
            },
            None,
        );
        let back = CallMemberContent::parse(&content.to_json()).unwrap();
        assert_eq!(back, content);
        let s = back.session().unwrap();
        let focus = s.mesh_focus().unwrap();
        assert_eq!(focus.node_key(), Some(node()));
        assert_eq!(focus.media.opus.bitrate, 16_000);
        assert_eq!(s.focus_active, ActiveFocus::MeshIroh);
    }

    #[test]
    fn leave_is_the_empty_object_and_parses_back_as_left() {
        assert_eq!(CallMemberContent::leave().to_json(), "{}");
        assert_eq!(
            CallMemberContent::parse("{}").unwrap(),
            CallMemberContent::leave()
        );
        // ruma's optional leave reason.
        let lost = CallMemberContent::parse(r#"{"leave_reason":"m.lost_connection"}"#).unwrap();
        assert_eq!(
            lost,
            CallMemberContent::Left(LeftMembership {
                leave_reason: Some("m.lost_connection".into())
            })
        );
        assert!(lost.session().is_none());
    }

    #[test]
    fn opus_defaults_fill_in_when_the_wire_omits_them() {
        let json = json!({
            "application": "m.call",
            "call_id": "",
            "device_id": "D",
            "foci_preferred": [{
                "type": "in.indiafoss.mesh.iroh",
                "node_id": hex32(&node()),
                "media": { "audio": "opus", "bitrate": 20000 }
            }],
            "focus_active": { "type": "in.indiafoss.mesh.iroh" }
        });
        let c = CallMemberContent::parse(&json.to_string()).unwrap();
        let opus = &c.session().unwrap().mesh_focus().unwrap().media.opus;
        assert_eq!(
            *opus,
            OpusParams {
                bitrate: 20_000,
                ..Default::default()
            }
        );
    }

    #[test]
    fn a_livekit_member_parses_but_offers_no_mesh_focus() {
        // Shape as ruma/js-sdk emit it for an Element Call member.
        let json = json!({
            "application": "m.call",
            "call_id": "",
            "scope": "m.room",
            "device_id": "ELEMENTX",
            "foci_preferred": [{
                "type": "livekit",
                "livekit_alias": "!room:example.org",
                "livekit_service_url": "https://livekit.example.org"
            }],
            "focus_active": { "type": "livekit", "focus_selection": "oldest_membership" },
            "created_ts": 1_700_000_000_000u64,
            "expires": 14_400_000
        });
        let c = CallMemberContent::parse(&json.to_string()).unwrap();
        let s = c.session().unwrap();
        assert!(s.mesh_focus().is_none());
        assert_eq!(
            s.focus_active,
            ActiveFocus::Livekit {
                focus_selection: "oldest_membership".into()
            }
        );
        // And it round-trips unchanged (we are a faithful reader, not a rewriter).
        let v: Value = serde_json::from_str(&c.to_json()).unwrap();
        assert_eq!(v, json);
    }

    #[test]
    fn an_unknown_focus_type_is_an_error_not_a_silent_leave() {
        let json = json!({
            "application": "m.call",
            "call_id": "",
            "device_id": "D",
            "foci_preferred": [{ "type": "org.example.sfu", "url": "x" }],
            "focus_active": { "type": "org.example.sfu" }
        });
        assert!(CallMemberContent::parse(&json.to_string()).is_err());
        // Likewise a session missing a required field.
        assert!(CallMemberContent::parse(r#"{"application":"m.call"}"#).is_err());
    }

    #[test]
    fn state_key_is_per_device_and_underscore_prefixed() {
        let node_hex = hex32(&node());
        assert_eq!(
            state_key(&format!("@n:{node_hex}"), "DEVICEID"),
            format!("_@n:{node_hex}_DEVICEID_m.call")
        );
    }

    #[test]
    fn expiry_uses_the_earlier_of_created_ts_and_origin_server_ts() {
        let mut s = match CallMemberContent::join(&node(), "D", OpusParams::default(), Some(1_000))
        {
            CallMemberContent::Session(s) => s,
            _ => unreachable!(),
        };
        // Join at origin 10_000, expires 1_000 → stale from 11_000.
        assert!(!s.is_expired(10_000, 10_999));
        assert!(s.is_expired(10_000, 11_000));
        // An update carries the original join as created_ts; the newer
        // origin_server_ts does not extend the life.
        s.created_ts = Some(10_000);
        assert!(s.is_expired(50_000, 11_000));
        // No expires → never stale by time.
        s.expires = None;
        assert!(!s.is_expired(0, u64::MAX));
    }

    #[test]
    fn mesh_members_enumerates_only_live_mesh_sessions() {
        let a = node();
        let mut b = node();
        b[0] ^= 0xff;
        let joined_a = CallMemberContent::join(&a, "DA", OpusParams::default(), Some(60_000));
        let joined_b = CallMemberContent::join(&b, "DB", OpusParams::default(), Some(60_000));
        let left = CallMemberContent::leave();
        let livekit = CallMemberContent::parse(
            &json!({
                "application": "m.call", "call_id": "", "device_id": "LK",
                "foci_preferred": [{ "type": "livekit", "livekit_alias": "a", "livekit_service_url": "u" }],
                "focus_active": { "type": "livekit", "focus_selection": "oldest_membership" }
            })
            .to_string(),
        )
        .unwrap();
        let bad_node = CallMemberContent::parse(
            &json!({
                "application": "m.call", "call_id": "", "device_id": "BAD",
                "foci_preferred": [{ "type": "in.indiafoss.mesh.iroh", "node_id": "NOT-HEX",
                                     "media": { "audio": "opus", "bitrate": 1 } }],
                "focus_active": { "type": "in.indiafoss.mesh.iroh" }
            })
            .to_string(),
        )
        .unwrap();
        let state = [
            ("_@n:a_DA_m.call", 1_000u64, &joined_a),
            ("_@n:b_DB_m.call", 100_000u64, &joined_b), // expired below
            ("_@n:c_DC_m.call", 1_000u64, &left),
            ("_@x:example.org_LK_m.call", 1_000u64, &livekit),
            ("_@n:d_BAD_m.call", 1_000u64, &bad_node),
        ];
        let at = |now| mesh_members(state.iter().map(|(k, t, c)| (*k, *t, *c)), now);
        // At 50_000 both mesh sessions are live (a: 1_000 + 60_000, b: 100_000
        // + 60_000); the left, LiveKit and malformed entries never appear.
        let members = at(50_000);
        assert_eq!(members.len(), 2, "{members:?}");
        assert_eq!(members[0].state_key, "_@n:a_DA_m.call");
        assert_eq!(members[0].node_id, a);
        assert_eq!(members[0].device_id, "DA");
        assert_eq!(members[0].opus, OpusParams::default());
        assert_eq!(members[1].node_id, b);
        // At 120_000 a has expired and only b is live.
        let members = at(120_000);
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].node_id, b);
        // At 160_000 both have.
        assert!(at(160_000).is_empty());
    }

    #[test]
    fn unhex32_is_strict() {
        let hex = hex32(&node());
        assert_eq!(unhex32(&hex), Some(node()));
        assert_eq!(unhex32(&hex.to_uppercase()), None);
        assert_eq!(unhex32(&hex[..63]), None);
        assert_eq!(unhex32(&format!("{hex}0")), None);
    }
}
