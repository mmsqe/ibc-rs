use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_json_abi::JsonAbi;
use ibc_proto::google::protobuf::Any;

use crate::error::Error;

use super::abi::pack_msg_data;

const ABI: &str = "[{\"inputs\":[{\"internalType\":\"bytes[]\",\"name\":\"payloads\",\"type\":\"bytes[]\"}],\"name\":\"batchCall\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]";
const FUNCTION_NAME: &str = "batchCall";

/// Get the JSON ABI for the Ethermint contract.
fn get_json_abi() -> JsonAbi {
    serde_json::from_str(ABI).unwrap()
}

fn pack_msgs(messages: &[Any], signer: &str) -> Result<Vec<Vec<u8>>, Error> {
    let mut packed = Vec::with_capacity(messages.len());

    for message in messages {
        let message_data = pack_msg_data(message, signer)?;
        packed.push(message_data);
    }

    Ok(packed)
}

pub fn pack_batch_call_data(messages: &[Any], signer: &str) -> Result<Vec<u8>, Error> {
    let packed_messages: Vec<_> = pack_msgs(messages, signer)?
        .into_iter()
        .map(|packed_message| DynSolValue::Bytes(packed_message))
        .collect();

    let abi = get_json_abi();

    let function = abi.function(FUNCTION_NAME).ok_or_else(|| {
        Error::ethermint_error(format!("Function {} not found in batch ABI", FUNCTION_NAME))
    })?;

    if function.len() != 1 {
        return Err(Error::ethermint_error(format!(
            "Function {} has {} overloads",
            FUNCTION_NAME,
            function.len()
        )));
    }

    let function = &function[0];

    function
        .abi_encode_input(&[DynSolValue::Array(packed_messages)])
        .map_err(|e| Error::abi_error(format!("Failed to encode inputs: {:?}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_abi() {
        let abi = get_json_abi();

        let function = abi
            .function(FUNCTION_NAME)
            .ok_or_else(|| {
                Error::ethermint_error(format!("Function {} not found in batch ABI", FUNCTION_NAME))
            })
            .unwrap();

        assert_eq!(function.len(), 1);
        let function = &function[0];

        let packed = function
            .abi_encode_input(&[DynSolValue::Array(vec![
                DynSolValue::Bytes(vec![1, 1]),
                DynSolValue::Bytes(vec![1, 1]),
            ])])
            .unwrap();

        println!("{:?}", packed);
    }
}
