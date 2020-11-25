use std::fmt;
use crate::err;

// Structs implementing the `JsonSerializable` trait are losslessly transformable to and from
// (optionally base64 encoded) JSON and back again.
//
// `JWT`, `ClaimSet`, `Claim`, and `JWTHeader` all implement this trait.
pub trait JsonSerializable: Sized {
    fn encode_str(&self) -> String;
    fn encode_b64(&self) -> String;
    // fn decode_str(input: &str) -> err::Result<Self>;
    fn decode_b64(input: &str) -> err::Result<Self>;
}