use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_json_abi::JsonAbi;
use ibc_proto::google::protobuf::Any;
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

/// A message to be sent to the Ethermint Relayer contract.
pub enum RelayerMessage<'a> {
    Single(&'a Any),
    Combo {
        msgs: &'a [Any],
        function_name: &'static str,
    },
}

impl<'a> RelayerMessage<'a> {
    /// Creates a new single message.
    pub fn new_single(msg: &'a Any) -> Self {
        Self::Single(msg)
    }

    /// Creates a new combo message.
    pub fn new_combo(msgs: &'a [Any], function_name: &'static str) -> Self {
        Self::Combo {
            msgs,
            function_name,
        }
    }

    /// Creates relayer messages (with combos if possible) from given messages.
    pub fn from_msgs(msgs: &'a [Any]) -> Vec<RelayerMessage<'a>> {
        trace!("creating relayer messages from {:?}", msgs);

        let mut relayer_msgs = vec![];

        let mut i = 0;

        while i < msgs.len() {
            if i == msgs.len() - 1 {
                relayer_msgs.push(RelayerMessage::new_single(&msgs[i]));
                break;
            }

            let current = &msgs[i];
            let next = &msgs[i + 1];

            match (current.type_url.as_str(), next.type_url.as_str()) {
                (
                    ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL,
                    ibc_relayer_types::core::ics03_connection::msgs::conn_open_init::TYPE_URL,
                ) => {
                    relayer_msgs.push(RelayerMessage::new_combo(
                        &msgs[i..(i + 2)],
                        "updateClientAndConnectionOpenInit",
                    ));
                    i += 2;
                }
                (
                    ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL,
                    ibc_relayer_types::core::ics03_connection::msgs::conn_open_try::TYPE_URL,
                ) => {
                    relayer_msgs.push(RelayerMessage::new_combo(
                        &msgs[i..(i + 2)],
                        "updateClientAndConnectionOpenTry",
                    ));
                    i += 2;
                }
                (
                    ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL,
                    ibc_relayer_types::core::ics03_connection::msgs::conn_open_ack::TYPE_URL,
                ) => {
                    relayer_msgs.push(RelayerMessage::new_combo(
                        &msgs[i..(i + 2)],
                        "updateClientAndConnectionOpenAck",
                    ));
                    i += 2;
                }
                (
                    ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL,
                    ibc_relayer_types::core::ics03_connection::msgs::conn_open_confirm::TYPE_URL,
                ) => {
                    relayer_msgs.push(RelayerMessage::new_combo(
                        &msgs[i..(i + 2)],
                        "updateClientAndConnectionOpenConfirm",
                    ));
                    i += 2;
                }
                (
                    ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL,
                    ibc_relayer_types::core::ics04_channel::msgs::chan_open_init::TYPE_URL,
                ) => {
                    relayer_msgs.push(RelayerMessage::new_combo(
                        &msgs[i..(i + 2)],
                        "updateClientAndChannelOpenInit",
                    ));
                    i += 2;
                }
                (
                    ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL,
                    ibc_relayer_types::core::ics04_channel::msgs::chan_open_try::TYPE_URL,
                ) => {
                    relayer_msgs.push(RelayerMessage::new_combo(
                        &msgs[i..(i + 2)],
                        "updateClientAndChannelOpenTry",
                    ));
                    i += 2;
                }
                (
                    ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL,
                    ibc_relayer_types::core::ics04_channel::msgs::chan_open_ack::TYPE_URL,
                ) => {
                    relayer_msgs.push(RelayerMessage::new_combo(
                        &msgs[i..(i + 2)],
                        "updateClientAndChannelOpenAck",
                    ));
                    i += 2;
                }
                (
                    ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL,
                    ibc_relayer_types::core::ics04_channel::msgs::chan_open_confirm::TYPE_URL,
                ) => {
                    relayer_msgs.push(RelayerMessage::new_combo(
                        &msgs[i..(i + 2)],
                        "updateClientAndChannelOpenConfirm",
                    ));
                    i += 2;
                }
                (
                    ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL,
                    ibc_relayer_types::core::ics04_channel::msgs::recv_packet::TYPE_URL,
                ) => {
                    relayer_msgs.push(RelayerMessage::new_combo(
                        &msgs[i..(i + 2)],
                        "updateClientAndRecvPacket",
                    ));
                    i += 2;
                }
                (
                    ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL,
                    ibc_relayer_types::core::ics04_channel::msgs::acknowledgement::TYPE_URL,
                ) => {
                    relayer_msgs.push(RelayerMessage::new_combo(
                        &msgs[i..(i + 2)],
                        "updateClientAndAcknowledgement",
                    ));
                    i += 2;
                }
                (
                    ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL,
                    ibc_relayer_types::core::ics04_channel::msgs::timeout::TYPE_URL,
                ) => {
                    relayer_msgs.push(RelayerMessage::new_combo(
                        &msgs[i..(i + 2)],
                        "updateClientAndTimeout",
                    ));
                    i += 2;
                }
                (
                    ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL,
                    ibc_relayer_types::core::ics04_channel::msgs::chan_close_init::TYPE_URL,
                ) => {
                    relayer_msgs.push(RelayerMessage::new_combo(
                        &msgs[i..(i + 2)],
                        "updateClientAndChannelCloseInit",
                    ));
                    i += 2;
                }
                (
                    ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL,
                    ibc_relayer_types::core::ics04_channel::msgs::chan_close_confirm::TYPE_URL,
                ) => {
                    relayer_msgs.push(RelayerMessage::new_combo(
                        &msgs[i..(i + 2)],
                        "updateClientAndChannelCloseConfirm",
                    ));
                    i += 2;
                }
                _ => {
                    relayer_msgs.push(RelayerMessage::new_single(current));
                    i += 1;
                }
            }
        }

        relayer_msgs
    }
}

/// Packs the given relayer message into bytes.
pub fn pack_data(relayer_message: RelayerMessage<'_>) -> Result<Vec<u8>, Error> {
    match relayer_message {
        RelayerMessage::Single(msg) => pack_msg_data(msg),
        RelayerMessage::Combo {
            msgs,
            function_name,
        } => pack_combo_data(msgs, function_name),
    }
}

/// Packs the given combo messages into bytes.
pub fn pack_combo_data(msgs: &[Any], function_name: &'static str) -> Result<Vec<u8>, Error> {
    trace!("packing combo data of type: {}", function_name);

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

    let function = &function[0];

    let mut args = Vec::with_capacity(msgs.len());
    for msg in msgs {
        args.push(DynSolValue::Bytes(msg.value.clone()));
    }

    function
        .abi_encode_input(&args)
        .map_err(|e| Error::abi_error(format!("Failed to encode inputs: {:?}", e)))
}

/// Packs the given message into bytes.
pub fn pack_msg_data(msg: &Any) -> Result<Vec<u8>, Error> {
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

    let function = &function[0];
    function
        .abi_encode_input(&[DynSolValue::Bytes(msg.value.clone())])
        .map_err(|e| Error::abi_error(format!("Failed to encode inputs: {:?}", e)))
}

#[cfg(test)]
mod tests {
    use alloy_dyn_abi::{DynSolValue, JsonAbiExt};

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
}
