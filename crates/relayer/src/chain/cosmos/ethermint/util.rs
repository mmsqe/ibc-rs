use ibc_proto::{
    ethermint::{evm::v1::ExtensionOptionsEthereumTx, types::v1::ExtensionOptionDynamicFeeTx},
    google::protobuf::Any,
};
use prost::Message;
use regex::Regex;

use crate::{chain::cosmos::types::config::TxConfig, error::Error};

/// Parses chain identifier from the given chain ID.
pub fn parse_chain_id(chain_id: &str) -> Result<String, Error> {
    let regex = Regex::new(r"^([a-z]{1,})_{1}([1-9][0-9]*)-{1}([1-9][0-9]*)$").unwrap();
    let captures = regex
        .captures(chain_id)
        .ok_or_else(|| Error::chain_identifier(chain_id.to_string()))?;

    if captures.len() != 4 || captures.get(1).unwrap().as_str() == "" {
        return Err(Error::chain_identifier(chain_id.to_string()));
    }

    Ok(captures.get(2).unwrap().as_str().to_string())
}

/// Returns the `gas_tip_cap` from `TxConfig`
pub fn get_gas_tip_cap(config: &TxConfig) -> Result<Option<String>, Error> {
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

/// Returns the EVM extension options.
pub fn get_evm_extension_options() -> Vec<Any> {
    let extension_option = ExtensionOptionsEthereumTx {};
    let extension_option_any = Any {
        type_url: "/ethermint.evm.v1.ExtensionOptionsEthereumTx".to_string(),
        value: extension_option.encode_to_vec(),
    };

    vec![extension_option_any]
}
