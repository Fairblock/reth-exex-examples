
use alloy_rlp::{BytesMut, Encodable, RlpDecodable, RlpEncodable};



#[derive(Clone, Debug, RlpEncodable, RlpDecodable, PartialEq)]
pub struct Message{
    pub(crate) key_share: Vec<u8>,
    pub(crate) id: Vec<u8>
}