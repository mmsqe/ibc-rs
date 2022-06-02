use core::convert::TryFrom;
use core::str::FromStr;
use core::time::Duration;
use eyre::eyre;
use http::uri::Uri;
use ibc::core::ics04_channel::packet::Sequence;
use ibc::core::ics24_host::identifier::{ChannelId, PortId};
use ibc::events::IbcEvent;
use ibc_proto::cosmos::base::v1beta1::Coin;
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::applications::fee::v1::query_client::QueryClient;
use ibc_proto::ibc::applications::fee::v1::{
    Fee as ProtoFee, IdentifiedPacketFees as ProtoIdentifiedPacketFees, MsgPayPacketFee,
    MsgPayPacketFeeAsync, MsgRegisterCounterpartyAddress, PacketFee as ProtoPacketFee,
    QueryCounterpartyAddressRequest, QueryIncentivizedPacketsForChannelRequest,
};
use ibc_proto::ibc::core::channel::v1::PacketId as ProtoPacketId;
use ibc_relayer::chain::cosmos::types::config::TxConfig;
use prost::{EncodeError, Message};
use tonic::Code;

use crate::error::{handle_generic_error, Error};
use crate::ibc::denom::Denom;
use crate::ibc::token::{TaggedTokenRef, Token};
use crate::relayer::transfer::build_transfer_message;
use crate::relayer::tx::simple_send_tx;
use crate::types::id::{TaggedChannelIdRef, TaggedPortIdRef};
use crate::types::tagged::{DualTagged, MonoTagged};
use crate::types::wallet::TaggedWallet;
use crate::types::wallet::{Wallet, WalletAddress};

pub async fn ibc_token_transfer_with_fee<SrcChain, DstChain>(
    tx_config: &MonoTagged<SrcChain, &TxConfig>,
    port_id: &TaggedPortIdRef<'_, SrcChain, DstChain>,
    channel_id: &TaggedChannelIdRef<'_, SrcChain, DstChain>,
    sender: &MonoTagged<SrcChain, &Wallet>,
    recipient: &MonoTagged<DstChain, &WalletAddress>,
    send_amount: &TaggedTokenRef<'_, SrcChain>,
    receive_fee: &TaggedTokenRef<'_, SrcChain>,
    ack_fee: &TaggedTokenRef<'_, SrcChain>,
    timeout_fee: &TaggedTokenRef<'_, SrcChain>,
    timeout: Duration,
) -> Result<Vec<IbcEvent>, Error> {
    let transfer_message =
        build_transfer_message(port_id, channel_id, sender, recipient, send_amount, timeout)?;

    let pay_message = build_pay_packet_message(
        port_id,
        channel_id,
        &sender.address(),
        receive_fee,
        ack_fee,
        timeout_fee,
    )?;

    let messages = vec![pay_message, transfer_message];

    let events = simple_send_tx(tx_config.value(), &sender.value().key, messages).await?;

    Ok(events)
}

pub async fn pay_packet_fee<Chain, Counterparty>(
    tx_config: &MonoTagged<Chain, &TxConfig>,
    port_id: &TaggedPortIdRef<'_, Chain, Counterparty>,
    channel_id: &TaggedChannelIdRef<'_, Chain, Counterparty>,
    sequence: &DualTagged<Chain, Counterparty, Sequence>,
    payer: &MonoTagged<Chain, &Wallet>,
    receive_fee: &TaggedTokenRef<'_, Chain>,
    ack_fee: &TaggedTokenRef<'_, Chain>,
    timeout_fee: &TaggedTokenRef<'_, Chain>,
) -> Result<(), Error> {
    let message = build_pay_packet_fee_async_message(
        port_id,
        channel_id,
        sequence,
        &payer.address(),
        receive_fee,
        ack_fee,
        timeout_fee,
    )?;

    simple_send_tx(tx_config.value(), &payer.value().key, vec![message]).await?;

    Ok(())
}

pub async fn register_counterparty_address<Chain, Counterparty>(
    tx_config: &MonoTagged<Chain, &TxConfig>,
    wallet: &MonoTagged<Chain, &Wallet>,
    counterparty_address: &MonoTagged<Counterparty, &WalletAddress>,
    channel_id: &TaggedChannelIdRef<'_, Chain, Counterparty>,
) -> Result<(), Error> {
    let message = build_register_counterparty_address_message(
        &wallet.address(),
        counterparty_address,
        channel_id,
    )?;

    let messages = vec![message.into_value()];

    simple_send_tx(tx_config.value(), &wallet.value().key, messages).await?;

    Ok(())
}

fn encode_message<M: Message>(message: &M) -> Result<Vec<u8>, EncodeError> {
    let mut buf = Vec::new();
    Message::encode(message, &mut buf)?;
    Ok(buf)
}

pub fn build_pay_packet_message<Chain, Counterparty>(
    port_id: &TaggedPortIdRef<Chain, Counterparty>,
    channel_id: &TaggedChannelIdRef<Chain, Counterparty>,
    payer: &MonoTagged<Chain, &WalletAddress>,
    receive_fee: &TaggedTokenRef<'_, Chain>,
    ack_fee: &TaggedTokenRef<'_, Chain>,
    timeout_fee: &TaggedTokenRef<'_, Chain>,
) -> Result<Any, Error> {
    const TYPE_URL: &str = "/ibc.applications.fee.v1.MsgPayPacketFee";

    let fee = ProtoFee {
        recv_fee: vec![Coin {
            denom: receive_fee.value().denom.to_string(),
            amount: receive_fee.value().amount.to_string(),
        }],
        ack_fee: vec![Coin {
            denom: ack_fee.value().denom.to_string(),
            amount: ack_fee.value().amount.to_string(),
        }],
        timeout_fee: vec![Coin {
            denom: timeout_fee.value().denom.to_string(),
            amount: timeout_fee.value().amount.to_string(),
        }],
    };

    let message = MsgPayPacketFee {
        fee: Some(fee),
        source_port_id: port_id.value().to_string(),
        source_channel_id: channel_id.value().to_string(),
        signer: payer.value().0.clone(),
        relayers: Vec::new(),
    };

    let encoded = encode_message(&message).map_err(handle_generic_error)?;

    Ok(Any {
        type_url: TYPE_URL.to_string(),
        value: encoded,
    })
}

pub fn build_pay_packet_fee_async_message<Chain, Counterparty>(
    port_id: &TaggedPortIdRef<Chain, Counterparty>,
    channel_id: &TaggedChannelIdRef<Chain, Counterparty>,
    sequence: &DualTagged<Chain, Counterparty, Sequence>,
    payer: &MonoTagged<Chain, &WalletAddress>,
    receive_fee: &TaggedTokenRef<'_, Chain>,
    ack_fee: &TaggedTokenRef<'_, Chain>,
    timeout_fee: &TaggedTokenRef<'_, Chain>,
) -> Result<Any, Error> {
    const TYPE_URL: &str = "/ibc.applications.fee.v1.MsgPayPacketFeeAsync";

    let fee = ProtoFee {
        recv_fee: vec![Coin {
            denom: receive_fee.value().denom.to_string(),
            amount: receive_fee.value().amount.to_string(),
        }],
        ack_fee: vec![Coin {
            denom: ack_fee.value().denom.to_string(),
            amount: ack_fee.value().amount.to_string(),
        }],
        timeout_fee: vec![Coin {
            denom: timeout_fee.value().denom.to_string(),
            amount: timeout_fee.value().amount.to_string(),
        }],
    };

    let packet_fee = ProtoPacketFee {
        fee: Some(fee),
        refund_address: payer.value().0.clone(),
        relayers: Vec::new(),
    };

    let packet_id = ProtoPacketId {
        port_id: port_id.value().to_string(),
        channel_id: channel_id.value().to_string(),
        sequence: (*sequence.value()).into(),
    };

    let message = MsgPayPacketFeeAsync {
        packet_fee: Some(packet_fee),
        packet_id: Some(packet_id),
    };

    let encoded = encode_message(&message).map_err(handle_generic_error)?;

    Ok(Any {
        type_url: TYPE_URL.to_string(),
        value: encoded,
    })
}

pub fn build_register_counterparty_address_message<Chain, Counterparty>(
    address: &MonoTagged<Chain, &WalletAddress>,
    counterparty_address: &MonoTagged<Counterparty, &WalletAddress>,
    channel_id: &TaggedChannelIdRef<Chain, Counterparty>,
) -> Result<MonoTagged<Chain, Any>, Error> {
    const TYPE_URL: &str = "/ibc.applications.fee.v1.MsgRegisterCounterpartyAddress";

    let message = MsgRegisterCounterpartyAddress {
        address: address.value().0.clone(),
        counterparty_address: counterparty_address.value().0.clone(),
        channel_id: channel_id.value().to_string(),
    };

    let encoded = encode_message(&message).map_err(handle_generic_error)?;

    let wrapped = Any {
        type_url: TYPE_URL.to_string(),
        value: encoded,
    };

    Ok(MonoTagged::new(wrapped))
}

pub async fn query_counterparty_address<Chain, Counterparty>(
    grpc_address: &Uri,
    channel_id: &TaggedChannelIdRef<'_, Chain, Counterparty>,
    address: &MonoTagged<Chain, &WalletAddress>,
) -> Result<Option<MonoTagged<Counterparty, WalletAddress>>, Error> {
    let mut client = QueryClient::connect(grpc_address.clone())
        .await
        .map_err(handle_generic_error)?;

    let request = QueryCounterpartyAddressRequest {
        channel_id: channel_id.value().to_string(),
        relayer_address: address.value().to_string(),
    };

    let result = client.counterparty_address(request).await;

    match result {
        Ok(response) => {
            let counterparty_address = WalletAddress(response.into_inner().counterparty_address);

            Ok(Some(MonoTagged::new(counterparty_address)))
        }
        Err(e) => {
            if e.code() == Code::NotFound {
                Ok(None)
            } else {
                Err(Error::generic(e.into()))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketId {
    pub channel_id: ChannelId,
    pub port_id: PortId,
    pub sequence: Sequence,
}

#[derive(Debug, Clone)]
pub struct PacketFee {
    pub recv_fee: Vec<Token>,
    pub ack_fee: Vec<Token>,
    pub timeout_fee: Vec<Token>,
    pub refund_address: WalletAddress,
}

#[derive(Debug, Clone)]
pub struct IdentifiedPacketFees {
    pub packet_id: PacketId,
    pub packet_fees: Vec<PacketFee>,
}

impl TryFrom<ProtoPacketId> for PacketId {
    type Error = Error;

    fn try_from(packet_id: ProtoPacketId) -> Result<Self, Error> {
        let channel_id =
            ChannelId::from_str(&packet_id.channel_id).map_err(handle_generic_error)?;

        let port_id = PortId::from_str(&packet_id.port_id).map_err(handle_generic_error)?;

        let sequence = Sequence::from(packet_id.sequence);

        Ok(PacketId {
            channel_id,
            port_id,
            sequence,
        })
    }
}

impl TryFrom<Coin> for Token {
    type Error = Error;

    fn try_from(fee: Coin) -> Result<Self, Error> {
        let denom = Denom::base(&fee.denom);
        let amount = u128::from_str(&fee.amount).map_err(handle_generic_error)?;

        Ok(Token::new(denom, amount))
    }
}

impl TryFrom<ProtoPacketFee> for PacketFee {
    type Error = Error;

    fn try_from(packet_fee: ProtoPacketFee) -> Result<Self, Error> {
        let fee = packet_fee
            .fee
            .ok_or_else(|| eyre!("expect fee field to be non-empty"))?;

        let recv_fee = fee
            .recv_fee
            .into_iter()
            .map(Token::try_from)
            .collect::<Result<_, _>>()?;

        let ack_fee = fee
            .ack_fee
            .into_iter()
            .map(Token::try_from)
            .collect::<Result<_, _>>()?;

        let timeout_fee = fee
            .timeout_fee
            .into_iter()
            .map(Token::try_from)
            .collect::<Result<_, _>>()?;

        let refund_address = WalletAddress(packet_fee.refund_address);

        Ok(PacketFee {
            recv_fee,
            ack_fee,
            timeout_fee,
            refund_address,
        })
    }
}

impl TryFrom<ProtoIdentifiedPacketFees> for IdentifiedPacketFees {
    type Error = Error;

    fn try_from(fees: ProtoIdentifiedPacketFees) -> Result<Self, Error> {
        let raw_packet_id = fees
            .packet_id
            .ok_or_else(|| eyre!("expect non-empty packet_id"))?;

        let packet_id = PacketId::try_from(raw_packet_id)?;
        let packet_fees = fees
            .packet_fees
            .into_iter()
            .map(PacketFee::try_from)
            .collect::<Result<_, _>>()?;

        Ok(IdentifiedPacketFees {
            packet_id,
            packet_fees,
        })
    }
}

pub async fn query_incentivized_packets<Chain, Counterparty>(
    grpc_address: &Uri,
    channel_id: &TaggedChannelIdRef<'_, Chain, Counterparty>,
    port_id: &TaggedPortIdRef<'_, Chain, Counterparty>,
) -> Result<Vec<IdentifiedPacketFees>, Error> {
    let mut client = QueryClient::connect(grpc_address.clone())
        .await
        .map_err(handle_generic_error)?;

    let request = QueryIncentivizedPacketsForChannelRequest {
        channel_id: channel_id.value().to_string(),
        port_id: port_id.value().to_string(),
        pagination: None,
        query_height: 0,
    };

    let response = client
        .incentivized_packets_for_channel(request)
        .await
        .map_err(handle_generic_error)?;

    let raw_packets = response.into_inner().incentivized_packets;

    let packets = raw_packets
        .into_iter()
        .map(IdentifiedPacketFees::try_from)
        .collect::<Result<_, _>>()?;

    Ok(packets)
}
