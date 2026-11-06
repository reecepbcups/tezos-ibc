//! PsUshuai block header: binary encoding and hash.
//! Layout from `octez-codec describe 025-PsUshuai.block_header binary schema`
//! and proto_025_PsUshuai/lib_protocol/block_header_repr.ml.

use serde::{Deserialize, Serialize};

use crate::{b58, blake2b256, Error, Hash};

/// Decoded block header (shell + PsUshuai protocol data).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub level: i32,
    pub proto: u8,
    pub predecessor: Hash,
    pub timestamp: i64,
    pub validation_pass: u8,
    pub operations_hash: Hash,
    pub fitness: Vec<Vec<u8>>,
    pub context: Hash,
    pub payload_hash: Hash,
    pub payload_round: i32,
    pub proof_of_work_nonce: [u8; 8],
    pub seed_nonce_hash: Option<Hash>,
    /// per_block_votes byte: 0 on, 1 off, 2 pass.
    pub per_block_votes: u8,
    /// 64 bytes, or 96 for a BLS baker.
    pub signature: Vec<u8>,
}

impl BlockHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(256);
        b.extend_from_slice(&self.level.to_be_bytes());
        b.push(self.proto);
        b.extend_from_slice(&self.predecessor);
        b.extend_from_slice(&self.timestamp.to_be_bytes());
        b.push(self.validation_pass);
        b.extend_from_slice(&self.operations_hash);
        let fit_len: usize = self.fitness.iter().map(|f| 4 + f.len()).sum();
        b.extend_from_slice(&(fit_len as u32).to_be_bytes());
        for f in &self.fitness {
            b.extend_from_slice(&(f.len() as u32).to_be_bytes());
            b.extend_from_slice(f);
        }
        b.extend_from_slice(&self.context);
        b.extend_from_slice(&self.payload_hash);
        b.extend_from_slice(&self.payload_round.to_be_bytes());
        b.extend_from_slice(&self.proof_of_work_nonce);
        match &self.seed_nonce_hash {
            Some(h) => {
                b.push(0xff);
                b.extend_from_slice(h);
            }
            None => b.push(0),
        }
        b.push(self.per_block_votes);
        // Last field, so no length prefix.
        b.extend_from_slice(&self.signature);
        b
    }

    /// Block hash: blake2b-256 of the full header bytes.
    pub fn hash(&self) -> Hash {
        blake2b256(&[&self.encode()])
    }

    /// Block round, the last fitness element (fitness_repr.ml `to_raw`).
    pub fn round(&self) -> Result<i32, Error> {
        match self.fitness.as_slice() {
            [v, _, _, _, r] if v.as_slice() == [2] && r.len() == 4 => {
                Ok(i32::from_be_bytes(r[..].try_into().unwrap()))
            }
            _ => Err(Error::BadFitness),
        }
    }

    pub fn from_rpc_json(s: &str) -> Result<Self, Error> {
        let r: RpcHeader = serde_json::from_str(s).map_err(|e| Error::Json(e.to_string()))?;
        r.try_into()
    }
}

/// Shape of `/chains/main/blocks/<b>/header`.
#[derive(Clone, Debug, Deserialize)]
pub struct RpcHeader {
    pub level: i32,
    pub proto: u8,
    pub predecessor: String,
    pub timestamp: String,
    pub validation_pass: u8,
    pub operations_hash: String,
    pub fitness: Vec<String>,
    pub context: String,
    pub payload_hash: String,
    pub payload_round: i32,
    pub proof_of_work_nonce: String,
    pub seed_nonce_hash: Option<String>,
    pub liquidity_baking_toggle_vote: String,
    pub signature: String,
}

impl TryFrom<RpcHeader> for BlockHeader {
    type Error = Error;

    fn try_from(r: RpcHeader) -> Result<Self, Error> {
        let hex_err = |s: &str| Error::Hex(s.into());
        Ok(BlockHeader {
            level: r.level,
            proto: r.proto,
            predecessor: b58::decode_fixed(&r.predecessor, b58::BLOCK_HASH)?,
            timestamp: parse_rfc3339(&r.timestamp)?,
            validation_pass: r.validation_pass,
            operations_hash: b58::decode_fixed(&r.operations_hash, b58::OPERATION_LIST_LIST_HASH)?,
            fitness: r
                .fitness
                .iter()
                .map(|f| hex::decode(f).map_err(|_| hex_err(f)))
                .collect::<Result<_, _>>()?,
            context: b58::decode_fixed(&r.context, b58::CONTEXT_HASH)?,
            payload_hash: b58::decode_fixed(&r.payload_hash, b58::PAYLOAD_HASH)?,
            payload_round: r.payload_round,
            proof_of_work_nonce: hex::decode(&r.proof_of_work_nonce)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| hex_err(&r.proof_of_work_nonce))?,
            seed_nonce_hash: r
                .seed_nonce_hash
                .as_deref()
                .map(|s| b58::decode_fixed(s, b58::NONCE_HASH))
                .transpose()?,
            per_block_votes: match r.liquidity_baking_toggle_vote.as_str() {
                "on" => 0,
                "off" => 1,
                "pass" => 2,
                v => return Err(Error::Json(format!("bad vote {v}"))),
            },
            signature: b58::decode_signature(&r.signature)?,
        })
    }
}

/// Parses `YYYY-MM-DDTHH:MM:SSZ` (the only form the RPC emits) to unix seconds.
fn parse_rfc3339(s: &str) -> Result<i64, Error> {
    let err = || Error::Json(format!("bad timestamp {s}"));
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[19] != b'Z' {
        return Err(err());
    }
    let num = |r: core::ops::Range<usize>| s[r].parse::<i64>().map_err(|_| err());
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    // Howard Hinnant's days_from_civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Ok(days * 86400 + hh * 3600 + mm * 60 + ss)
}

#[cfg(test)]
mod tests {
    use super::parse_rfc3339;

    #[test]
    fn timestamps() {
        for (s, want) in [
            ("1970-01-01T00:00:00Z", 0),
            ("2018-06-30T16:07:32Z", 1530374852),
            ("2024-02-29T23:59:59Z", 1709251199),
        ] {
            assert_eq!(parse_rfc3339(s).unwrap(), want, "{s}");
        }
        assert!(parse_rfc3339("2024-02-29 23:59:59").is_err());
    }
}
