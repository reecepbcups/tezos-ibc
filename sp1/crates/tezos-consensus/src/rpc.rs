//! Conversions from RPC JSON (`/chains/main/blocks/<b>/operations/0`) to [`Attestation`].

use serde_json::Value;

use crate::attestation::{dal_bits_from_decimal, Attestation, CommitteeMember, ConsensusContent};
use crate::{b58, Error};

fn field<'a>(v: &'a Value, k: &str) -> Result<&'a Value, Error> {
    v.get(k).ok_or_else(|| Error::Json(format!("missing {k}")))
}

fn str_field<'a>(v: &'a Value, k: &str) -> Result<&'a str, Error> {
    field(v, k)?
        .as_str()
        .ok_or_else(|| Error::Json(format!("{k} not a string")))
}

fn int_field(v: &Value, k: &str) -> Result<i64, Error> {
    field(v, k)?
        .as_i64()
        .ok_or_else(|| Error::Json(format!("{k} not an int")))
}

fn slot(v: &Value) -> Result<u16, Error> {
    u16::try_from(int_field(v, "slot")?).map_err(|_| Error::Json("bad slot".into()))
}

fn content(v: &Value) -> Result<ConsensusContent, Error> {
    Ok(ConsensusContent {
        level: int_field(v, "level")? as i32,
        round: int_field(v, "round")? as i32,
        block_payload_hash: b58::decode_fixed(
            str_field(v, "block_payload_hash")?,
            b58::PAYLOAD_HASH,
        )?,
    })
}

fn dal(v: &Value) -> Result<Option<Vec<u8>>, Error> {
    v.get("dal_attestation")
        .map(|d| dal_bits_from_decimal(d.as_str().unwrap_or("x")))
        .transpose()
}

/// Parses one operation. Errors on anything but a single attestation(-with-dal) or aggregate.
pub fn attestation_from_rpc(op: &Value) -> Result<Attestation, Error> {
    let branch = b58::decode_fixed(str_field(op, "branch")?, b58::BLOCK_HASH)?;
    let signature = b58::decode_signature(str_field(op, "signature")?)?;
    let contents = field(op, "contents")?
        .as_array()
        .ok_or_else(|| Error::Json("contents".into()))?;
    let [c] = contents.as_slice() else {
        return Err(Error::Json("expected one content".into()));
    };
    match str_field(c, "kind")? {
        "attestation" | "attestation_with_dal" => Ok(Attestation::Single {
            branch,
            slot: slot(c)?,
            content: content(c)?,
            dal: dal(c)?,
            signature,
        }),
        "attestations_aggregate" => Ok(Attestation::Aggregate {
            branch,
            content: content(field(c, "consensus_content")?)?,
            committee: field(c, "committee")?
                .as_array()
                .ok_or_else(|| Error::Json("committee".into()))?
                .iter()
                .map(|m| {
                    Ok(CommitteeMember {
                        slot: slot(m)?,
                        dal: dal(m)?,
                    })
                })
                .collect::<Result<_, Error>>()?,
            signature,
        }),
        k => Err(Error::Json(format!("not an attestation: {k}"))),
    }
}
