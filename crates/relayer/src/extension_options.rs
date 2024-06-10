use ibc_proto::google::protobuf::Any;
use prost::Message;
use serde_derive::{Deserialize, Serialize};

use crate::error::Error;

pub const TYPE_URL: &str = "/ethermint.types.v1.ExtensionOptionDynamicFeeTx";

// ExtensionOptionDynamicFeeTx is an extension option used with ethermint dynamic fee tx.
// protobuf message: https://github.com/evmos/ethermint/blob/main/proto/ethermint/types/v1/dynamic_fee.proto
#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct ExtensionOptionDynamicFeeTx {
    #[prost(string, tag = "1")]
    pub max_priority_price: String,
}

impl ExtensionOptionDynamicFeeTx {
    pub fn to_any(&self) -> Result<Any, Error> {
        let mut buf = Vec::new();
        Message::encode(self, &mut buf)
            .map_err(|e| Error::protobuf_encode("ExtensionOptionDynamicFeeTx".into(), e))?;
        Ok(Any {
            type_url: TYPE_URL.to_string(),
            value: buf,
        })
    }
}
