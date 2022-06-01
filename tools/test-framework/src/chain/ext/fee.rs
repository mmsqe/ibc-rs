use core::time::Duration;
use ibc::core::ics04_channel::packet::Sequence;
use ibc::events::IbcEvent;

use crate::chain::driver::ChainDriver;
use crate::chain::tagged::TaggedChainDriverExt;
use crate::error::Error;
use crate::ibc::token::TaggedTokenRef;
use crate::relayer::fee::{
    ibc_token_transfer_with_fee, pay_packet_fee, query_counterparty_address,
    register_counterparty_address,
};
use crate::types::id::{TaggedChannelIdRef, TaggedPortIdRef};
use crate::types::tagged::*;
use crate::types::wallet::{Wallet, WalletAddress};

pub trait ChainFeeMethodsExt<Chain> {
    fn ibc_token_transfer_with_fee<Counterparty>(
        &self,
        port_id: &TaggedPortIdRef<'_, Chain, Counterparty>,
        channel_id: &TaggedChannelIdRef<'_, Chain, Counterparty>,
        sender: &MonoTagged<Chain, &Wallet>,
        recipient: &MonoTagged<Counterparty, &WalletAddress>,
        send_amount: &TaggedTokenRef<'_, Chain>,
        receive_fee: &TaggedTokenRef<'_, Chain>,
        ack_fee: &TaggedTokenRef<'_, Chain>,
        timeout_fee: &TaggedTokenRef<'_, Chain>,
        timeout: Duration,
    ) -> Result<Vec<IbcEvent>, Error>;

    fn pay_packet_fee<Counterparty>(
        &self,
        port_id: &TaggedPortIdRef<'_, Chain, Counterparty>,
        channel_id: &TaggedChannelIdRef<'_, Chain, Counterparty>,
        sequence: &DualTagged<Chain, Counterparty, Sequence>,
        payer: &MonoTagged<Chain, &Wallet>,
        receive_fee: &TaggedTokenRef<'_, Chain>,
        ack_fee: &TaggedTokenRef<'_, Chain>,
        timeout_fee: &TaggedTokenRef<'_, Chain>,
    ) -> Result<(), Error>;

    fn register_counterparty_address<Counterparty>(
        &self,
        wallet: &MonoTagged<Chain, &Wallet>,
        counterparty_address: &MonoTagged<Counterparty, &WalletAddress>,
        channel_id: &TaggedChannelIdRef<'_, Chain, Counterparty>,
    ) -> Result<(), Error>;

    fn query_counterparty_address<Counterparty>(
        &self,
        channel_id: &TaggedChannelIdRef<'_, Chain, Counterparty>,
        address: &MonoTagged<Chain, &WalletAddress>,
    ) -> Result<Option<MonoTagged<Counterparty, WalletAddress>>, Error>;
}

impl<'a, Chain: Send> ChainFeeMethodsExt<Chain> for MonoTagged<Chain, &'a ChainDriver> {
    fn ibc_token_transfer_with_fee<Counterparty>(
        &self,
        port_id: &TaggedPortIdRef<'_, Chain, Counterparty>,
        channel_id: &TaggedChannelIdRef<'_, Chain, Counterparty>,
        sender: &MonoTagged<Chain, &Wallet>,
        recipient: &MonoTagged<Counterparty, &WalletAddress>,
        send_amount: &TaggedTokenRef<'_, Chain>,
        receive_fee: &TaggedTokenRef<'_, Chain>,
        ack_fee: &TaggedTokenRef<'_, Chain>,
        timeout_fee: &TaggedTokenRef<'_, Chain>,
        timeout: Duration,
    ) -> Result<Vec<IbcEvent>, Error> {
        self.value().runtime.block_on(ibc_token_transfer_with_fee(
            &self.tx_config(),
            port_id,
            channel_id,
            sender,
            recipient,
            send_amount,
            receive_fee,
            ack_fee,
            timeout_fee,
            timeout,
        ))
    }

    fn pay_packet_fee<Counterparty>(
        &self,
        port_id: &TaggedPortIdRef<'_, Chain, Counterparty>,
        channel_id: &TaggedChannelIdRef<'_, Chain, Counterparty>,
        sequence: &DualTagged<Chain, Counterparty, Sequence>,
        payer: &MonoTagged<Chain, &Wallet>,
        receive_fee: &TaggedTokenRef<'_, Chain>,
        ack_fee: &TaggedTokenRef<'_, Chain>,
        timeout_fee: &TaggedTokenRef<'_, Chain>,
    ) -> Result<(), Error> {
        self.value().runtime.block_on(pay_packet_fee(
            &self.tx_config(),
            port_id,
            channel_id,
            sequence,
            payer,
            receive_fee,
            ack_fee,
            timeout_fee,
        ))
    }

    fn register_counterparty_address<Counterparty>(
        &self,
        wallet: &MonoTagged<Chain, &Wallet>,
        counterparty_address: &MonoTagged<Counterparty, &WalletAddress>,
        channel_id: &TaggedChannelIdRef<'_, Chain, Counterparty>,
    ) -> Result<(), Error> {
        self.value().runtime.block_on(register_counterparty_address(
            &self.tx_config(),
            wallet,
            counterparty_address,
            channel_id,
        ))
    }

    fn query_counterparty_address<Counterparty>(
        &self,
        channel_id: &TaggedChannelIdRef<'_, Chain, Counterparty>,
        address: &MonoTagged<Chain, &WalletAddress>,
    ) -> Result<Option<MonoTagged<Counterparty, WalletAddress>>, Error> {
        self.value().runtime.block_on(query_counterparty_address(
            &self.tx_config().value().grpc_address,
            channel_id,
            address,
        ))
    }
}
