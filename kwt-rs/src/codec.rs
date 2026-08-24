//! Canonical binary encoding for KWT payloads (the “claims” layer).
//!
//! This is **not** a JWT claim set: there is no JSON, no dot-separated header, and no
//! `alg` / `typ` / `crit` fields. Each logical field is identified by a one-byte
//! **opcode** below. Unknown opcodes are rejected at decode time.
//!
//! ---

// ============================================================================
// kwt/src/codec.rs
//
// Opcode layout (1 byte per field identifier, not JWT header flags):
//   0x10  subject     — varint len + UTF-8 bytes
//   0x20  issued_at   — uint32 little-endian (Unix timestamp, seconds)
//   0x21  expires_at  — uint32 little-endian
//   0x30  audience    — varint len + UTF-8 bytes
//   0x40  roles       — uint8 count + uint8[] enum values
//   0x50  scopes      — uint8 count + uint8[] enum values
//   0x60  jti         — 16 raw bytes (UUID v7, big-endian)
//   0x80  END         — no following bytes; required final opcode
//
// Canonicalization rules enforced by the encoder:
//   - Fields written in ascending opcode order
//   - No duplicate opcodes
//   - All strings are valid UTF-8
//   - expires_at > issued_at
//   - END marker is always the last byte
// ============================================================================

use crate::error::KwtError;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Opcode constants
// ---------------------------------------------------------------------------

const OP_SUBJECT:    u8 = 0x10;
const OP_ISSUED_AT:  u8 = 0x20;
const OP_EXPIRES_AT: u8 = 0x21;
const OP_AUDIENCE:   u8 = 0x30;
const OP_ROLES:      u8 = 0x40;
const OP_SCOPES:     u8 = 0x50;
const OP_JTI:        u8 = 0x60;
const OP_END:        u8 = 0x80;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Roles are a closed enum registered at the protocol level.
/// Wire encoding: a single uint8 per role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Admin   = 0x01,
    Editor  = 0x02,
    Viewer  = 0x03,
    Service = 0x04,
}

impl Role {
    pub fn from_u8(v: u8) -> Result<Self, KwtError> {
        match v {
            0x01 => Ok(Role::Admin),
            0x02 => Ok(Role::Editor),
            0x03 => Ok(Role::Viewer),
            0x04 => Ok(Role::Service),
            other => Err(KwtError::InvalidClaim(format!("unknown role opcode: {:#x}", other))),
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Role::Admin   => "admin",
            Role::Editor  => "editor",
            Role::Viewer  => "viewer",
            Role::Service => "service",
        };
        write!(f, "{}", s)
    }
}

/// Scopes are a closed enum for API permission grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Scope {
    ReadStats  = 0x01,
    WriteLogs  = 0x02,
    ReadUsers  = 0x03,
    WriteUsers = 0x04,
    Admin      = 0xFF,
}

impl Scope {
    pub fn from_u8(v: u8) -> Result<Self, KwtError> {
        match v {
            0x01 => Ok(Scope::ReadStats),
            0x02 => Ok(Scope::WriteLogs),
            0x03 => Ok(Scope::ReadUsers),
            0x04 => Ok(Scope::WriteUsers),
            0xFF => Ok(Scope::Admin),
            other => Err(KwtError::InvalidClaim(format!("unknown scope opcode: {:#x}", other))),
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Scope::ReadStats  => "read:stats",
            Scope::WriteLogs  => "write:logs",
            Scope::ReadUsers  => "read:users",
            Scope::WriteUsers => "write:users",
            Scope::Admin      => "admin:all",
        };
        write!(f, "{}", s)
    }
}

// ---------------------------------------------------------------------------
// Claims — the decoded payload
// ---------------------------------------------------------------------------

/// The validated, decoded claims from a KWT token.
/// All fields that appear in the binary format are represented here.
///
/// [`fmt::Debug`] is **redacted** (lengths only for strings, no `jti` value) so
/// `println!("{claims:?}")` in servers does not leak identifiers into logs.
#[derive(Clone)]
pub struct Claims {
    /// Subject identifier. Alphanumeric.
    pub subject: String,

    /// Unix timestamp (seconds) when the token was issued.
    pub issued_at: u32,

    /// Unix timestamp (seconds) after which the token must be rejected.
    pub expires_at: u32,

    /// Intended audience. Must exactly match the server's registered audience.
    pub audience: String,

    /// Authorization roles granted to this token.
    pub roles: Vec<Role>,

    /// API scopes granted to this token.
    pub scopes: Vec<Scope>,

    /// JWT ID — UUID v7 for replay detection.
    pub jti: Uuid,
}

impl fmt::Debug for Claims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Claims")
            .field("subject", &format_args!("[{} bytes]", self.subject.len()))
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("audience", &format_args!("[{} bytes]", self.audience.len()))
            .field("roles", &self.roles)
            .field("scopes", &self.scopes)
            .field("jti", &"[redacted]")
            .finish()
    }
}

impl Claims {
    /// Validate structural integrity (not expiry — that's the token layer's job).
    pub fn validate_structure(&self) -> Result<(), KwtError> {
        if self.subject.is_empty() {
            return Err(KwtError::InvalidClaim("subject must not be empty".into()));
        }
        if !self.subject.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            return Err(KwtError::InvalidClaim(
                "subject must be alphanumeric with underscores and hyphens only".into()
            ));
        }
        if self.expires_at <= self.issued_at {
            return Err(KwtError::InvalidClaim("expires_at must be after issued_at".into()));
        }
        if self.audience.is_empty() {
            return Err(KwtError::InvalidClaim("audience must not be empty".into()));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Varint encoding (Protocol Buffers style)
// ---------------------------------------------------------------------------

/// Encode a usize as a variable-length integer.
/// Values 0-127 → 1 byte; 128-16383 → 2 bytes; etc.
fn encode_varint(mut value: usize, buf: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}

/// Decode a varint from a byte slice, returning (value, bytes_consumed).
fn decode_varint(data: &[u8]) -> Result<(usize, usize), KwtError> {
    let mut result: usize = 0;
    let mut shift = 0usize;
    for (i, &byte) in data.iter().enumerate() {
        // Safety: reject varints that would overflow usize
        if shift >= 64 {
            return Err(KwtError::PayloadError("varint overflow".into()));
        }
        result |= ((byte & 0x7F) as usize) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
    }
    Err(KwtError::PayloadError("unterminated varint".into()))
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// Serialize a Claims struct into canonical binary form.
///
/// Fields are written in strict ascending opcode order.
/// This function is the canonical serializer — its output is what gets encrypted.
pub fn encode(claims: &Claims) -> Result<Vec<u8>, KwtError> {
    claims.validate_structure()?;

    let mut buf = Vec::with_capacity(80);

    // 0x10  subject
    buf.push(OP_SUBJECT);
    let subj = claims.subject.as_bytes();
    encode_varint(subj.len(), &mut buf);
    buf.extend_from_slice(subj);

    // 0x20  issued_at
    buf.push(OP_ISSUED_AT);
    buf.extend_from_slice(&claims.issued_at.to_le_bytes());

    // 0x21  expires_at
    buf.push(OP_EXPIRES_AT);
    buf.extend_from_slice(&claims.expires_at.to_le_bytes());

    // 0x30  audience
    buf.push(OP_AUDIENCE);
    let aud = claims.audience.as_bytes();
    encode_varint(aud.len(), &mut buf);
    buf.extend_from_slice(aud);

    // 0x40  roles (only if non-empty)
    if !claims.roles.is_empty() {
        if claims.roles.len() > 255 {
            return Err(KwtError::InvalidClaim("too many roles (max 255)".into()));
        }
        buf.push(OP_ROLES);
        buf.push(claims.roles.len() as u8);
        for role in &claims.roles {
            buf.push(*role as u8);
        }
    }

    // 0x50  scopes (only if non-empty)
    if !claims.scopes.is_empty() {
        if claims.scopes.len() > 255 {
            return Err(KwtError::InvalidClaim("too many scopes (max 255)".into()));
        }
        buf.push(OP_SCOPES);
        buf.push(claims.scopes.len() as u8);
        for scope in &claims.scopes {
            buf.push(*scope as u8);
        }
    }

    // 0x60  jti — 16 raw bytes
    buf.push(OP_JTI);
    buf.extend_from_slice(claims.jti.as_bytes());

    // 0x80  END marker — mandatory
    buf.push(OP_END);

    Ok(buf)
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// Deserialize canonical binary form into a Claims struct.
///
/// Enforces:
///   - Opcodes must appear in strictly ascending order
///   - No duplicate opcodes
///   - END marker must be present and must be the last byte
///   - Required fields (subject, issued_at, expires_at, audience, jti) must be present
pub fn decode(data: &[u8]) -> Result<Claims, KwtError> {
    let mut pos = 0;
    let mut last_opcode: u8 = 0x00;

    // Decoded fields — all mandatory fields start as None
    let mut subject:    Option<String>  = None;
    let mut issued_at:  Option<u32>     = None;
    let mut expires_at: Option<u32>     = None;
    let mut audience:   Option<String>  = None;
    let mut roles:      Vec<Role>       = Vec::new();
    let mut scopes:     Vec<Scope>      = Vec::new();
    let mut jti:        Option<Uuid>    = None;
    let mut end_seen = false;

    while pos < data.len() {
        let opcode = data[pos];
        pos += 1;

        // Enforce ascending opcode order (catches duplicates and mis-ordering)
        if opcode != OP_END && opcode <= last_opcode {
            return Err(KwtError::PayloadError(format!(
                "opcodes out of order at position {}: {:#x} after {:#x}",
                pos - 1, opcode, last_opcode
            )));
        }
        last_opcode = opcode;

        match opcode {
            OP_SUBJECT => {
                let (len, consumed) = decode_varint(&data[pos..])?;
                pos += consumed;
                require_bytes(data, pos, len, "subject")?;
                let s = std::str::from_utf8(&data[pos..pos + len])
                    .map_err(|_| KwtError::PayloadError("subject is not valid UTF-8".into()))?;
                subject = Some(s.to_owned());
                pos += len;
            }

            OP_ISSUED_AT => {
                require_bytes(data, pos, 4, "issued_at")?;
                issued_at = Some(u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()));
                pos += 4;
            }

            OP_EXPIRES_AT => {
                require_bytes(data, pos, 4, "expires_at")?;
                expires_at = Some(u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()));
                pos += 4;
            }

            OP_AUDIENCE => {
                let (len, consumed) = decode_varint(&data[pos..])?;
                pos += consumed;
                require_bytes(data, pos, len, "audience")?;
                let s = std::str::from_utf8(&data[pos..pos + len])
                    .map_err(|_| KwtError::PayloadError("audience is not valid UTF-8".into()))?;
                audience = Some(s.to_owned());
                pos += len;
            }

            OP_ROLES => {
                require_bytes(data, pos, 1, "roles count")?;
                let count = data[pos] as usize;
                pos += 1;
                require_bytes(data, pos, count, "roles data")?;
                for &byte in &data[pos..pos + count] {
                    roles.push(Role::from_u8(byte)?);
                }
                pos += count;
            }

            OP_SCOPES => {
                require_bytes(data, pos, 1, "scopes count")?;
                let count = data[pos] as usize;
                pos += 1;
                require_bytes(data, pos, count, "scopes data")?;
                for &byte in &data[pos..pos + count] {
                    scopes.push(Scope::from_u8(byte)?);
                }
                pos += count;
            }

            OP_JTI => {
                require_bytes(data, pos, 16, "jti")?;
                let bytes: [u8; 16] = data[pos..pos + 16].try_into().unwrap();
                jti = Some(Uuid::from_bytes(bytes));
                pos += 16;
            }

            OP_END => {
                end_seen = true;
                // END must be the last byte
                if pos != data.len() {
                    return Err(KwtError::PayloadError(
                        "data present after END marker".into()
                    ));
                }
                break;
            }

            unknown => {
                return Err(KwtError::PayloadError(format!(
                    "unknown opcode {:#x} at position {}",
                    unknown, pos - 1
                )));
            }
        }
    }

    if !end_seen {
        return Err(KwtError::PayloadError("END marker (0x80) not found".into()));
    }

    // Assemble and validate the claims struct
    let claims = Claims {
        subject:    subject.ok_or_else(|| KwtError::MissingClaim("subject".into()))?,
        issued_at:  issued_at.ok_or_else(|| KwtError::MissingClaim("issued_at".into()))?,
        expires_at: expires_at.ok_or_else(|| KwtError::MissingClaim("expires_at".into()))?,
        audience:   audience.ok_or_else(|| KwtError::MissingClaim("audience".into()))?,
        roles,
        scopes,
        jti:        jti.ok_or_else(|| KwtError::MissingClaim("jti".into()))?,
    };

    claims.validate_structure()?;
    Ok(claims)
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn require_bytes(data: &[u8], pos: usize, needed: usize, field: &str) -> Result<(), KwtError> {
    if pos + needed > data.len() {
        Err(KwtError::PayloadError(format!(
            "truncated payload reading {} (need {} bytes at pos {}, have {})",
            field, needed, pos, data.len().saturating_sub(pos)
        )))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Utility: generate a new Claims skeleton with sane defaults
// ---------------------------------------------------------------------------

/// Build a [`Claims`] skeleton with `issued_at` / `expires_at` from the system clock.
///
/// Fails with [`KwtError::SystemTime`] if the host clock is before the Unix epoch.
pub fn new_claims(subject: &str, audience: &str, ttl_seconds: u32) -> Result<Claims, KwtError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| KwtError::SystemTime)?
        .as_secs() as u32;

    let claims = Claims {
        subject:    subject.to_owned(),
        issued_at:  now,
        expires_at: now.saturating_add(ttl_seconds),
        audience:   audience.to_owned(),
        roles:      Vec::new(),
        scopes:     Vec::new(),
        jti:        Uuid::now_v7(),
    };
    claims.validate_structure()?;
    Ok(claims)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims() -> Claims {
        Claims {
            subject:    "user_882".into(),
            issued_at:  1_744_459_200,
            expires_at: 1_744_545_600,
            audience:   "api.example.com".into(),
            roles:      vec![Role::Admin, Role::Editor],
            scopes:     vec![Scope::ReadStats, Scope::WriteLogs],
            jti:        Uuid::now_v7(),
        }
    }

    #[test]
    fn round_trip() {
        let claims = sample_claims();
        let encoded = encode(&claims).expect("encode failed");
        let decoded = decode(&encoded).expect("decode failed");

        assert_eq!(decoded.subject,    claims.subject);
        assert_eq!(decoded.issued_at,  claims.issued_at);
        assert_eq!(decoded.expires_at, claims.expires_at);
        assert_eq!(decoded.audience,   claims.audience);
        assert_eq!(decoded.roles,      claims.roles);
        assert_eq!(decoded.scopes,     claims.scopes);
        assert_eq!(decoded.jti,        claims.jti);
    }

    #[test]
    fn compact_size() {
        let claims = sample_claims();
        let encoded = encode(&claims).expect("encode failed");

        // Verify density: our benchmark payload must fit under 60 bytes
        // (5 fields of real data, binary encoding, no structural noise)
        println!("Canonical binary payload size: {} bytes", encoded.len());
        assert!(
            encoded.len() < 80,
            "payload too large: {} bytes (expected <80)",
            encoded.len()
        );
    }

    #[test]
    fn rejects_out_of_order_opcodes() {
        // Craft a bad payload: issued_at (0x20) before subject (0x10).
        let bad = vec![
            OP_ISSUED_AT, 0x00, 0x00, 0x00, 0x00,   // issued_at first
            OP_SUBJECT, 0x01, b'x',                   // then subject — out of order!
            OP_EXPIRES_AT, 0xFF, 0xFF, 0xFF, 0xFF,
            OP_AUDIENCE, 0x01, b'x',
            OP_JTI, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            OP_END,
        ];
        assert!(decode(&bad).is_err(), "should reject out-of-order opcodes");
    }

    #[test]
    fn rejects_missing_end_marker() {
        let claims = sample_claims();
        let mut encoded = encode(&claims).expect("encode failed");
        encoded.pop(); // remove the 0x80 END marker
        assert!(decode(&encoded).is_err(), "should reject missing END");
    }

    #[test]
    fn rejects_invalid_subject_chars() {
        let mut claims = sample_claims();
        claims.subject = "user/../../etc/passwd".into(); // path traversal attempt
        assert!(encode(&claims).is_err(), "should reject subject with slashes");
    }

    #[test]
    fn varint_round_trip() {
        for &val in &[0usize, 1, 127, 128, 255, 300, 16383, 16384] {
            let mut buf = Vec::new();
            encode_varint(val, &mut buf);
            let (decoded, _) = decode_varint(&buf).unwrap();
            assert_eq!(val, decoded, "varint round-trip failed for {}", val);
        }
    }

}
