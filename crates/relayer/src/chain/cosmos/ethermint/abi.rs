use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_json_abi::JsonAbi;
use bech32::ToBase32;
use ibc_proto::{
    google::protobuf::Any,
    ibc::core::{
        channel::v1::{
            MsgAcknowledgement, MsgChannelCloseConfirm, MsgChannelCloseInit, MsgChannelOpenAck,
            MsgChannelOpenConfirm, MsgChannelOpenInit, MsgChannelOpenTry, MsgRecvPacket,
            MsgTimeout, MsgTimeoutOnClose,
        },
        client::v1::{MsgCreateClient, MsgSubmitMisbehaviour, MsgUpdateClient, MsgUpgradeClient},
        connection::v1::{
            MsgConnectionOpenAck, MsgConnectionOpenConfirm, MsgConnectionOpenInit,
            MsgConnectionOpenTry,
        },
    },
};
use prost::Message;
use tracing::trace;

use crate::error::Error;

const ABI: &str = "[{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"acknowledgement\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"channelCloseConfirm\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"channelCloseInit\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"channelOpenAck\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"channelOpenConfirm\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"channelOpenInit\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"channelOpenTry\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"connectionOpenAck\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"connectionOpenConfirm\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"connectionOpenInit\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"connectionOpenTry\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"createClient\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"recvPacket\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"submitMisbehaviour\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"timeout\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"timeoutOnClose\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"updateClient\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"data2\",\"type\":\"bytes\"}],\"name\":\"updateClientAndAcknowledgement\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"data2\",\"type\":\"bytes\"}],\"name\":\"updateClientAndChannelCloseConfirm\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"data2\",\"type\":\"bytes\"}],\"name\":\"updateClientAndChannelCloseInit\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"data2\",\"type\":\"bytes\"}],\"name\":\"updateClientAndChannelOpenAck\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"data2\",\"type\":\"bytes\"}],\"name\":\"updateClientAndChannelOpenConfirm\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"data2\",\"type\":\"bytes\"}],\"name\":\"updateClientAndChannelOpenInit\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"data2\",\"type\":\"bytes\"}],\"name\":\"updateClientAndChannelOpenTry\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"data2\",\"type\":\"bytes\"}],\"name\":\"updateClientAndConnectionOpenAck\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"data2\",\"type\":\"bytes\"}],\"name\":\"updateClientAndConnectionOpenConfirm\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"data2\",\"type\":\"bytes\"}],\"name\":\"updateClientAndConnectionOpenInit\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"data2\",\"type\":\"bytes\"}],\"name\":\"updateClientAndConnectionOpenTry\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"data2\",\"type\":\"bytes\"}],\"name\":\"updateClientAndRecvPacket\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"data2\",\"type\":\"bytes\"}],\"name\":\"updateClientAndTimeout\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"upgradeClient\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"payable\",\"type\":\"function\"}]";

/// Get the JSON ABI for the Ethermint contract.
fn get_json_abi() -> JsonAbi {
    serde_json::from_str(ABI).unwrap()
}

/// Returns the function name for given message type in ABI.
fn get_function_name(msg: &Any) -> Result<&'static str, Error> {
    match msg.type_url.as_str() {
        ibc_relayer_types::core::ics02_client::msgs::create_client::TYPE_URL => Ok("createClient"),
        ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL => Ok("updateClient"),
        ibc_relayer_types::core::ics02_client::msgs::upgrade_client::TYPE_URL => {
            Ok("upgradeClient")
        }
        ibc_relayer_types::core::ics02_client::msgs::misbehaviour::TYPE_URL => {
            Ok("submitMisbehaviour")
        }
        ibc_relayer_types::core::ics03_connection::msgs::conn_open_init::TYPE_URL => {
            Ok("connectionOpenInit")
        }
        ibc_relayer_types::core::ics03_connection::msgs::conn_open_try::TYPE_URL => {
            Ok("connectionOpenTry")
        }
        ibc_relayer_types::core::ics03_connection::msgs::conn_open_ack::TYPE_URL => {
            Ok("connectionOpenAck")
        }
        ibc_relayer_types::core::ics03_connection::msgs::conn_open_confirm::TYPE_URL => {
            Ok("connectionOpenConfirm")
        }
        ibc_relayer_types::core::ics04_channel::msgs::chan_open_init::TYPE_URL => {
            Ok("channelOpenInit")
        }
        ibc_relayer_types::core::ics04_channel::msgs::chan_open_try::TYPE_URL => {
            Ok("channelOpenTry")
        }
        ibc_relayer_types::core::ics04_channel::msgs::chan_open_ack::TYPE_URL => {
            Ok("channelOpenAck")
        }
        ibc_relayer_types::core::ics04_channel::msgs::chan_open_confirm::TYPE_URL => {
            Ok("channelOpenConfirm")
        }
        ibc_relayer_types::core::ics04_channel::msgs::chan_close_init::TYPE_URL => {
            Ok("channelCloseInit")
        }
        ibc_relayer_types::core::ics04_channel::msgs::chan_close_confirm::TYPE_URL => {
            Ok("channelCloseConfirm")
        }
        ibc_relayer_types::core::ics04_channel::msgs::recv_packet::TYPE_URL => Ok("recvPacket"),
        ibc_relayer_types::core::ics04_channel::msgs::acknowledgement::TYPE_URL => {
            Ok("acknowledgement")
        }
        ibc_relayer_types::core::ics04_channel::msgs::timeout::TYPE_URL => Ok("timeout"),
        ibc_relayer_types::core::ics04_channel::msgs::timeout_on_close::TYPE_URL => {
            Ok("timeoutOnClose")
        }
        _ => Err(Error::ethermint_error("Unknown message type".to_string())),
    }
}

fn get_bech32_address(hex_address: &str, account_prefix: &str) -> Result<String, Error> {
    let hex_address = if hex_address.starts_with("0x") {
        hex_address.strip_prefix("0x").unwrap()
    } else {
        hex_address
    };

    let address_bytes =
        hex::decode(hex_address).map_err(|e| Error::from_hex_error(format!("{:?}", e)))?;

    bech32::encode(
        account_prefix,
        address_bytes.to_base32(),
        bech32::Variant::Bech32,
    )
    .map_err(|e| Error::to_bech32_error(format!("{:?}", e)))
}

#[allow(deprecated)]
fn set_signer(msg: &Any, signer: &str, account_prefix: &str) -> Result<Any, Error> {
    let signer = get_bech32_address(signer, account_prefix)?;

    match msg.type_url.as_str() {
        ibc_relayer_types::core::ics02_client::msgs::create_client::TYPE_URL => {
            let mut message: MsgCreateClient = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL => {
            let mut message: MsgUpdateClient = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics02_client::msgs::upgrade_client::TYPE_URL => {
            let mut message: MsgUpgradeClient = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics02_client::msgs::misbehaviour::TYPE_URL => {
            let mut message: MsgSubmitMisbehaviour = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics03_connection::msgs::conn_open_init::TYPE_URL => {
            let mut message: MsgConnectionOpenInit = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics03_connection::msgs::conn_open_try::TYPE_URL => {
            let mut message: MsgConnectionOpenTry = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics03_connection::msgs::conn_open_ack::TYPE_URL => {
            let mut message: MsgConnectionOpenAck = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics03_connection::msgs::conn_open_confirm::TYPE_URL => {
            let mut message: MsgConnectionOpenConfirm = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics04_channel::msgs::chan_open_init::TYPE_URL => {
            let mut message: MsgChannelOpenInit = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics04_channel::msgs::chan_open_try::TYPE_URL => {
            let mut message: MsgChannelOpenTry = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics04_channel::msgs::chan_open_ack::TYPE_URL => {
            let mut message: MsgChannelOpenAck = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics04_channel::msgs::chan_open_confirm::TYPE_URL => {
            let mut message: MsgChannelOpenConfirm = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics04_channel::msgs::chan_close_init::TYPE_URL => {
            let mut message: MsgChannelCloseInit = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics04_channel::msgs::chan_close_confirm::TYPE_URL => {
            let mut message: MsgChannelCloseConfirm = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics04_channel::msgs::recv_packet::TYPE_URL => {
            let mut message: MsgRecvPacket = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics04_channel::msgs::acknowledgement::TYPE_URL => {
            let mut message: MsgAcknowledgement = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics04_channel::msgs::timeout::TYPE_URL => {
            let mut message: MsgTimeout = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        ibc_relayer_types::core::ics04_channel::msgs::timeout_on_close::TYPE_URL => {
            let mut message: MsgTimeoutOnClose = Message::decode(msg.value.as_ref())
                .map_err(|err| Error::prost_decode_error(format!("{:?}", err)))?;
            message.signer = signer;

            Ok(Any {
                type_url: msg.type_url.to_owned(),
                value: message.encode_to_vec(),
            })
        }
        _ => Err(Error::ethermint_error("Unknown message type".to_string())),
    }
}

/// Packs the given message into bytes.
pub fn pack_msg_data(msg: &Any, signer: &str, account_prefix: &str) -> Result<Vec<u8>, Error> {
    trace!("packing data of type: {}", msg.type_url);

    let function_name = get_function_name(msg)?;
    let abi = get_json_abi();

    let function = abi.function(function_name).ok_or_else(|| {
        Error::ethermint_error(format!("Function {} not found in ABI", function_name))
    })?;

    if function.len() != 1 {
        return Err(Error::ethermint_error(format!(
            "Function {} has {} overloads",
            function_name,
            function.len()
        )));
    }

    let msg = set_signer(msg, signer, account_prefix)?;

    let function = &function[0];
    function
        .abi_encode_input(&[DynSolValue::Bytes(msg.value)])
        .map_err(|e| Error::abi_error(format!("Failed to encode inputs: {:?}", e)))
}

#[cfg(test)]
mod tests {
    use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
    use bech32::ToBase32;

    use super::*;

    #[test]
    fn test_abi() {
        let abi = get_json_abi();
        assert_eq!(abi.functions.len(), 31);

        assert_eq!(1, abi.functions.get("createClient").unwrap().len());

        let create_client_fn = &abi.functions.get("createClient").unwrap()[0];
        assert_eq!(create_client_fn.inputs.len(), 1);

        let value = DynSolValue::Bytes(vec![1]);

        let encoded = create_client_fn.abi_encode_input(&[value]).unwrap();
        println!("encoded: {:?}", encoded);

        let expected = vec![
            61, 248, 58, 250, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_bech_32() {
        let addr = "0x6F1805D56bF05b7be10857F376A5b1c160C8f72C";

        let addr = if addr.starts_with("0x") {
            addr.strip_prefix("0x").unwrap()
        } else {
            addr
        };

        let data = hex::decode(addr).unwrap();
        let encoded = bech32::encode("crc", data.to_base32(), bech32::Variant::Bech32).unwrap();
        println!("{}", encoded);

        let func = get_bech32_address(addr, "crc").unwrap();

        println!("{}", func);
    }
}
