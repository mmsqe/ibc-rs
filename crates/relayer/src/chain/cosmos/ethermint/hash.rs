use bytes::Bytes;
use ibc_proto::ethermint::evm::v1::DynamicFeeTx;
use primitive_types::U256;
use rlp::RlpStream;
use tiny_keccak::{Hasher, Keccak};

use crate::error::Error;

/// Computes keccak256 hash of the given bytes.
pub fn keccak256_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

/// Returns the raw transaction rlp bytes for given `DynamicFeeTx`
pub fn get_transaction_raw(tx: &DynamicFeeTx) -> Result<Vec<u8>, Error> {
    let tx_rlp = get_dynamic_fee_tx_rlp_signature(tx)?;

    let mut raw = Vec::with_capacity(1 + tx_rlp.len());
    raw.push(2u8); // Transaction type for `DynamicFeeTx`
    raw.extend_from_slice(&tx_rlp);

    Ok(raw)
}

/// Returns the transaction hash for the given `DynamicFeeTx`.
#[allow(dead_code)]
pub fn get_transaction_hash(tx: &DynamicFeeTx) -> Result<String, Error> {
    let tx_rlp = get_dynamic_fee_tx_rlp_signature(tx)?;

    let mut hash_input = Vec::with_capacity(1 + tx_rlp.len());
    hash_input.push(2u8); // Transaction type for `DynamicFeeTx`
    hash_input.extend_from_slice(&tx_rlp);

    let hash = keccak256_hash(&hash_input);
    Ok(format!("0x{}", hex::encode(hash)))
}

/// Returns the signature hash for the given `DynamicFeeTx`.
pub fn get_signature_hash(tx: &DynamicFeeTx) -> Result<[u8; 32], Error> {
    let tx_rlp = get_dynamic_fee_tx_rlp_base(tx)?;

    let mut hash_input = Vec::with_capacity(1 + tx_rlp.len());
    hash_input.push(2u8); // Transaction type for `DynamicFeeTx`
    hash_input.extend_from_slice(&tx_rlp);

    Ok(keccak256_hash(&hash_input))
}

/// Populates RLP stream with all the base fields of the given `DynamicFeeTx`.
fn populate_dynamic_fee_tx_rlp_base(tx: &DynamicFeeTx, rlp: &mut RlpStream) -> Result<(), Error> {
    let chain_id = U256::from_dec_str(&tx.chain_id)
        .map_err(|e| Error::chain_identifier(format!("{:?}", e)))?;
    rlp.append(&chain_id);

    rlp.append(&tx.nonce);

    let gas_tip_cap = U256::from_dec_str(&tx.gas_tip_cap).unwrap();
    rlp.append(&gas_tip_cap);

    let gas_fee_cap = U256::from_dec_str(&tx.gas_fee_cap).unwrap();
    rlp.append(&gas_fee_cap);

    rlp.append(&tx.gas);

    let to_str = if tx.to.starts_with("0x") {
        &tx.to[2..]
    } else {
        &tx.to
    };
    let to_vec = hex::decode(to_str).map_err(|e| Error::from_hex_error(format!("{:?}", e)))?;
    assert_eq!(to_vec.len(), 20);
    rlp.append(&to_vec);

    let value = U256::from_dec_str(&tx.value).unwrap();
    rlp.append(&value);

    rlp.append(&tx.data);

    rlp.begin_list(0);

    Ok(())
}

/// Returns the RLP encoding of the given `DynamicFeeTx` (only with base fields).
fn get_dynamic_fee_tx_rlp_base(tx: &DynamicFeeTx) -> Result<Bytes, Error> {
    let mut rlp = RlpStream::new();

    rlp.begin_unbounded_list();
    populate_dynamic_fee_tx_rlp_base(tx, &mut rlp)?;
    rlp.finalize_unbounded_list();

    Ok(rlp.out().freeze())
}

/// Returns the RLP encoding of the given `DynamicFeeTx` (with base and signature fields).
fn get_dynamic_fee_tx_rlp_signature(tx: &DynamicFeeTx) -> Result<Bytes, Error> {
    let mut rlp = RlpStream::new();

    rlp.begin_unbounded_list();
    populate_dynamic_fee_tx_rlp_base(tx, &mut rlp)?;

    rlp.append(&U256::from(tx.v[0]));
    rlp.append(&U256::from_big_endian(&tx.r));
    rlp.append(&U256::from_big_endian(&tx.s));

    rlp.finalize_unbounded_list();

    Ok(rlp.out().freeze())
}
