use bytes::Bytes;
use ibc_proto::{
    cosmos::{
        base::v1beta1::Coin,
        tx::v1beta1::{AuthInfo, Fee, TxBody, TxRaw},
    },
    ethermint::evm::v1::{DynamicFeeTx, ExtensionOptionsEthereumTx, MsgEthereumTx},
    google::protobuf::Any,
};
use primitive_types::U256;
use prost::Message;
use regex::Regex;
use rlp::RlpStream;
use tendermint_rpc::{endpoint::broadcast::tx_sync::Response, HttpClient};
use tiny_keccak::{Hasher, Keccak};

use crate::{
    error::Error, extension_options::ExtensionOptionDynamicFeeTx, keyring::Secp256k1KeyPair,
};

use super::{
    tx::broadcast_tx_sync,
    types::{account::Account, config::TxConfig},
};

/// Returns input data prefix bytes depending on the message type.
fn get_prefix_bytes(msg: &Any) -> Result<u32, Error> {
    match msg.type_url.as_str() {
        ibc_relayer_types::core::ics02_client::msgs::create_client::TYPE_URL => Ok(2),
        ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL => Ok(3),
        ibc_relayer_types::core::ics02_client::msgs::upgrade_client::TYPE_URL => Ok(4),
        ibc_relayer_types::core::ics02_client::msgs::misbehaviour::TYPE_URL => Ok(5),
        ibc_relayer_types::core::ics03_connection::msgs::conn_open_init::TYPE_URL => Ok(6),
        ibc_relayer_types::core::ics03_connection::msgs::conn_open_try::TYPE_URL => Ok(7),
        ibc_relayer_types::core::ics03_connection::msgs::conn_open_ack::TYPE_URL => Ok(8),
        ibc_relayer_types::core::ics03_connection::msgs::conn_open_confirm::TYPE_URL => Ok(9),
        ibc_relayer_types::core::ics04_channel::msgs::chan_open_init::TYPE_URL => Ok(10),
        ibc_relayer_types::core::ics04_channel::msgs::chan_open_try::TYPE_URL => Ok(11),
        ibc_relayer_types::core::ics04_channel::msgs::chan_open_ack::TYPE_URL => Ok(12),
        ibc_relayer_types::core::ics04_channel::msgs::chan_open_confirm::TYPE_URL => Ok(13),
        ibc_relayer_types::core::ics04_channel::msgs::chan_close_init::TYPE_URL => Ok(14),
        ibc_relayer_types::core::ics04_channel::msgs::chan_close_confirm::TYPE_URL => Ok(15),
        ibc_relayer_types::core::ics04_channel::msgs::recv_packet::TYPE_URL => Ok(16),
        ibc_relayer_types::core::ics04_channel::msgs::acknowledgement::TYPE_URL => Ok(17),
        ibc_relayer_types::core::ics04_channel::msgs::timeout::TYPE_URL => Ok(18),
        ibc_relayer_types::core::ics04_channel::msgs::timeout_on_close::TYPE_URL => Ok(19),
        _ => Err(Error::ethermint_error("Unknown message type".to_string())),
    }
}

/// Parses chain identifier from the given chain ID.
fn parse_chain_id(chain_id: &str) -> Result<String, Error> {
    let regex = Regex::new(r"^([a-z]{1,})_{1}([1-9][0-9]*)-{1}([1-9][0-9]*)$").unwrap();
    let captures = regex
        .captures(chain_id)
        .ok_or_else(|| Error::chain_identifier(chain_id.to_string()))?;

    if captures.len() != 4 || captures.get(1).unwrap().as_str() == "" {
        return Err(Error::chain_identifier(chain_id.to_string()));
    }

    Ok(captures.get(2).unwrap().as_str().to_string())
}

/// Prepares prefixed data for the given message.
fn prepare_prefixed_data(msg: &Any) -> Result<Vec<u8>, Error> {
    let prefix = get_prefix_bytes(msg)?.to_le_bytes();

    let mut prefixed_data = Vec::with_capacity(msg.value.len() + 4);
    prefixed_data.extend_from_slice(&prefix);
    prefixed_data.extend_from_slice(&msg.value);

    Ok(prefixed_data)
}

/// Returns the `gas_tip_cap` from `TxConfig`
fn get_gas_tip_cap(config: &TxConfig) -> Result<Option<String>, Error> {
    if config.extension_options.is_empty() {
        return Ok(None);
    }

    let extention_option = config.extension_options.get(0).unwrap();

    if extention_option.type_url != crate::extension_options::TYPE_URL {
        return Ok(None);
    }

    let dynamic_fee_ext_op = ExtensionOptionDynamicFeeTx::decode(&*extention_option.value)
        .map_err(|e| Error::protobuf_decode("ExtensionOptionDynamicFeeTx".into(), e))?;

    Ok(Some(dynamic_fee_ext_op.max_priority_price))
}

/// Computes keccak256 hash of the given bytes.
pub fn keccak256_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

/// Returns the transaction hash for the given `DynamicFeeTx`.
fn get_transaction_hash(tx: &DynamicFeeTx) -> Result<String, Error> {
    let tx_rlp = get_dynamic_fee_tx_rlp_signature(tx)?;

    let mut hash_input = Vec::with_capacity(1 + tx_rlp.len());
    hash_input.push(2u8); // Transaction type for `DynamicFeeTx`
    hash_input.extend_from_slice(&tx_rlp);

    let hash = keccak256_hash(&hash_input);
    Ok(format!("0x{}", hex::encode(hash)))
}

/// Returns the signature hash for the given `DynamicFeeTx`.
fn get_signature_hash(tx: &DynamicFeeTx) -> Result<[u8; 32], Error> {
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

/// Returns the EVM extension options.
fn get_evm_extension_options() -> Vec<Any> {
    let extension_option = ExtensionOptionsEthereumTx {};
    let extension_option_any = Any {
        type_url: "/ethermint.evm.v1.ExtensionOptionsEthereumTx".to_string(),
        value: extension_option.encode_to_vec(),
    };

    vec![extension_option_any]
}

/// Builds the `DynamicFeeTx` for the given message.
fn build_dynamic_fee_tx(
    message: &Any,
    message_index: usize,
    account: &Account,
    config: &TxConfig,
) -> Result<DynamicFeeTx, Error> {
    let nonce = account.sequence.to_u64() + message_index as u64;

    let mut tx = DynamicFeeTx::default();

    tx.chain_id = parse_chain_id(config.chain_id.as_str())?;
    tx.nonce = nonce;
    tx.to = config
        .precompiled_contract_address
        .as_ref()
        .unwrap()
        .clone();
    tx.value = "0".to_string();
    tx.data = prepare_prefixed_data(message)?;
    tx.gas_fee_cap = config.gas_config.gas_price.price.to_string();
    tx.gas = config.gas_config.max_gas;
    tx.accesses = Vec::new();

    if let Some(gas_tip_cap) = get_gas_tip_cap(config)? {
        tx.gas_tip_cap = gas_tip_cap;
    }

    Ok(tx)
}

/// Builds the `MsgEthereumTx` for the given `DynamicFeeTx`.
fn build_ethereum_tx(
    dynamic_fee_tx: &DynamicFeeTx,
    key_pair: &Secp256k1KeyPair,
) -> Result<MsgEthereumTx, Error> {
    let dynamic_fee_tx_any = Any {
        type_url: "/ethermint.evm.v1.DynamicFeeTx".to_string(),
        value: dynamic_fee_tx.encode_to_vec(),
    };

    let mut eth_tx = MsgEthereumTx::default();
    eth_tx.data = Some(dynamic_fee_tx_any);
    eth_tx.from = key_pair.address().to_vec();
    eth_tx.hash = get_transaction_hash(&dynamic_fee_tx)?;

    Ok(eth_tx)
}

/// Converts the given `MsgEthereumTx` to `Any`.
fn get_ethereum_tx_any(eth_tx: &MsgEthereumTx) -> Any {
    Any {
        type_url: "/ethermint.evm.v1.MsgEthereumTx".to_string(),
        value: eth_tx.encode_to_vec(),
    }
}

/// Signs the given `DynamicFeeTx` with the given key pair.
fn sign_dynamic_fee_tx(
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

pub async fn send_txs(
    rpc_client: &HttpClient,
    config: &TxConfig,
    key_pair: &Secp256k1KeyPair,
    account: &Account,
    messages: &[Any],
) -> Result<Response, Error> {
    let mut gas_limit = 0;
    let mut fee = U256::zero();

    let mut transactions = Vec::with_capacity(messages.len());

    for (i, message) in messages.iter().enumerate() {
        let mut dynamic_fee_tx = build_dynamic_fee_tx(message, i, account, config)?;
        sign_dynamic_fee_tx(&mut dynamic_fee_tx, key_pair)?;

        let eth_tx = build_ethereum_tx(&dynamic_fee_tx, key_pair)?;
        let eth_tx_any = get_ethereum_tx_any(&eth_tx);

        gas_limit += dynamic_fee_tx.gas;
        fee += U256::from_dec_str(&dynamic_fee_tx.gas_fee_cap).unwrap() * dynamic_fee_tx.gas;

        transactions.push(eth_tx_any);
    }

    let tx_body = TxBody {
        messages: transactions,
        memo: "".to_string(),
        timeout_height: 0,
        extension_options: get_evm_extension_options(),
        non_critical_extension_options: Vec::new(),
    };

    let auth_info = AuthInfo {
        signer_infos: Vec::new(),
        fee: Some(Fee {
            amount: vec![Coin {
                denom: config.gas_config.gas_price.denom.clone(),
                amount: fee.to_string(),
            }],
            gas_limit,
            payer: "".to_string(),
            granter: "".to_string(),
        }),
        tip: None,
    };

    let tx_raw = TxRaw {
        body_bytes: tx_body.encode_to_vec(),
        auth_info_bytes: auth_info.encode_to_vec(),
        signatures: Vec::new(),
    };

    broadcast_tx_sync(rpc_client, &config.rpc_address, tx_raw.encode_to_vec()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    use ibc_proto::{
        ethermint::evm::v1::{DynamicFeeTx, MsgEthereumTx},
        google::protobuf::Any,
    };
    use prost::Message;

    #[test]
    fn test_eth_tx() {
        let eth_tx_any = Any {
            type_url: "/ethermint.evm.v1.MsgEthereumTx".to_string(),
            value: vec![
                10, 142, 4, 10, 30, 47, 101, 116, 104, 101, 114, 109, 105, 110, 116, 46, 101, 118,
                109, 46, 118, 49, 46, 68, 121, 110, 97, 109, 105, 99, 70, 101, 101, 84, 120, 18,
                235, 3, 10, 3, 55, 55, 55, 26, 7, 49, 48, 48, 48, 48, 48, 48, 34, 17, 49, 48, 48,
                48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 40, 160, 194, 30, 50, 42,
                48, 120, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
                48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 54,
                53, 58, 1, 48, 66, 148, 3, 2, 0, 0, 0, 10, 35, 47, 105, 98, 99, 46, 99, 111, 114,
                101, 46, 99, 108, 105, 101, 110, 116, 46, 118, 49, 46, 77, 115, 103, 67, 114, 101,
                97, 116, 101, 67, 108, 105, 101, 110, 116, 18, 232, 2, 10, 176, 1, 10, 43, 47, 105,
                98, 99, 46, 108, 105, 103, 104, 116, 99, 108, 105, 101, 110, 116, 115, 46, 116,
                101, 110, 100, 101, 114, 109, 105, 110, 116, 46, 118, 49, 46, 67, 108, 105, 101,
                110, 116, 83, 116, 97, 116, 101, 18, 128, 1, 10, 11, 99, 104, 97, 105, 110, 109,
                97, 105, 110, 45, 49, 18, 4, 8, 1, 16, 3, 26, 4, 8, 128, 234, 73, 34, 4, 8, 128,
                223, 110, 42, 2, 8, 40, 50, 0, 58, 4, 8, 1, 16, 15, 66, 25, 10, 9, 8, 1, 24, 1, 32,
                1, 42, 1, 0, 18, 12, 10, 2, 0, 1, 16, 33, 24, 4, 32, 12, 48, 1, 66, 25, 10, 9, 8,
                1, 24, 1, 32, 1, 42, 1, 0, 18, 12, 10, 2, 0, 1, 16, 32, 24, 1, 32, 1, 48, 1, 74, 7,
                117, 112, 103, 114, 97, 100, 101, 74, 16, 117, 112, 103, 114, 97, 100, 101, 100,
                73, 66, 67, 83, 116, 97, 116, 101, 80, 1, 88, 1, 18, 134, 1, 10, 46, 47, 105, 98,
                99, 46, 108, 105, 103, 104, 116, 99, 108, 105, 101, 110, 116, 115, 46, 116, 101,
                110, 100, 101, 114, 109, 105, 110, 116, 46, 118, 49, 46, 67, 111, 110, 115, 101,
                110, 115, 117, 115, 83, 116, 97, 116, 101, 18, 84, 10, 12, 8, 204, 174, 239, 168,
                6, 16, 136, 162, 157, 227, 1, 18, 34, 10, 32, 169, 138, 16, 16, 201, 65, 195, 26,
                126, 226, 115, 110, 193, 67, 238, 139, 198, 81, 136, 110, 39, 123, 233, 200, 111,
                230, 171, 10, 160, 136, 235, 236, 26, 32, 38, 112, 169, 244, 89, 186, 176, 166,
                243, 224, 87, 206, 144, 6, 191, 147, 113, 43, 223, 225, 186, 46, 239, 49, 63, 42,
                153, 250, 226, 37, 132, 118, 26, 42, 99, 114, 99, 49, 54, 122, 48, 104, 101, 114,
                122, 57, 57, 56, 57, 52, 54, 119, 114, 54, 53, 57, 108, 114, 56, 52, 99, 56, 99,
                53, 53, 54, 100, 97, 53, 53, 100, 99, 51, 52, 104, 104, 26, 64, 55, 101, 56, 99,
                100, 55, 53, 48, 55, 99, 100, 48, 98, 48, 56, 49, 50, 51, 51, 50, 57, 102, 51, 100,
                100, 98, 56, 98, 97, 97, 101, 102, 57, 54, 53, 55, 99, 53, 49, 99, 55, 54, 51, 56,
                51, 55, 102, 56, 98, 49, 56, 54, 48, 99, 51, 101, 57, 97, 57, 55, 54, 98, 55, 51,
                42, 32, 26, 2, 15, 23, 25, 3, 2, 5, 5, 7, 5, 21, 26, 14, 3, 26, 20, 5, 31, 3, 7,
                21, 24, 7, 24, 20, 20, 26, 13, 29, 20, 20,
            ],
        };
        let eth_tx = MsgEthereumTx::decode(eth_tx_any.value.as_slice()).unwrap();

        let tx_any = eth_tx.data.unwrap();
        let mut tx = DynamicFeeTx::decode(tx_any.value.as_slice()).unwrap();

        tx.r = rlp::encode(&U256::from_dec_str("12").unwrap()).to_vec();
        tx.s = rlp::encode(&U256::from_dec_str("12").unwrap()).to_vec();
        tx.v = rlp::encode(&U256::from_dec_str("12").unwrap()).to_vec();

        let tx_hash = get_transaction_hash(&tx).unwrap();

        assert_eq!(
            tx_hash,
            "0xe31e4a83ed8f267113d3cb7f5e652e739f1016a0e19e87fd9f10daaad9e1769e"
        );
    }
}
