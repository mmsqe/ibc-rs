use ibc_proto::ethermint::evm::v1::DynamicFeeTx;

use crate::{error::Error, keyring::Secp256k1KeyPair};

use super::hash::get_signature_hash;

/// Signs the given `DynamicFeeTx` with the given key pair.
pub fn sign_dynamic_fee_tx(
    dynamic_fee_tx: &mut DynamicFeeTx,
    key_pair: &Secp256k1KeyPair,
) -> Result<(), Error> {
    let signature_hash = get_signature_hash(dynamic_fee_tx)?;
    let (recovery_id, signature) = key_pair
        .sign_recoverable_prehashed(signature_hash)
        .map_err(|e| Error::keyring_error(e))?;

    dynamic_fee_tx.r = signature[0..32].to_vec();
    dynamic_fee_tx.s = signature[32..64].to_vec();
    dynamic_fee_tx.v = vec![recovery_id as u8];

    Ok(())
}
