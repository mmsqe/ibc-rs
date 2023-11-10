mod abi;
mod gas;
mod hash;
mod sign;
mod tx;
mod util;

pub use self::abi::RelayerMessage;

use ibc_proto::google::protobuf::Any;
use prost::Message;
use tendermint_rpc::{endpoint::broadcast::tx_sync::Response, HttpClient};
use tracing::trace;

use crate::{error::Error, keyring::Secp256k1KeyPair};

use self::tx::build_tx_raw;

use super::{
    tx::broadcast_tx_sync,
    types::{account::Account, config::TxConfig},
};

/// Sends the given messages as a `MsgEthereumTx` transaction.
pub async fn send_txs(
    rpc_client: &HttpClient,
    config: &TxConfig,
    key_pair: &Secp256k1KeyPair,
    account: &Account,
    messages: &[Any],
) -> Result<Response, Error> {
    let tx_raw = build_tx_raw(config, key_pair, account, messages).await?;

    trace!("broadcasting transaction: {:?}", tx_raw);
    broadcast_tx_sync(rpc_client, &config.rpc_address, tx_raw.encode_to_vec()).await
}

#[cfg(test)]
mod tests {
    use crate::chain::cosmos::ethermint::hash::get_transaction_hash;

    use ibc_proto::{
        ethermint::evm::v1::{DynamicFeeTx, MsgEthereumTx},
        google::protobuf::Any,
    };
    use primitive_types::U256;
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
