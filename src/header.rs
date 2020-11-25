use serde_json::Value;
use std::fmt;

use crate::err;

#[derive(Debug)]
pub enum Typ {
    None,
    JWT,
}

#[derive(Debug)]
pub enum Alg {
    None,
}

#[derive(Debug)]
pub enum Cty {
    None,
    JWT,
}

#[derive(Debug)]
pub struct JWTHeader {
    pub typ: Typ,
    pub cty: Cty,
    pub alg: Alg,
}

/// The `JWTHeader` struct represents a JWT header, known in the spec as a JOSE header. Although
/// you may construct with `JWTHeader` structs directly, it is usually better to use the public
/// `JWT` struct and its accompanying methods instead.
impl JWTHeader {

    /// Encodes self into a plaintext JOSE Header suitable for display.
    pub fn encode_str(&self) -> String {
        String::from("{\"alg\": ") + "\"none\"" + "}"
    }

    /// Encodes self into a valid JOSE Header.
    pub fn encode(&self) -> String {
        let header: String = self.encode_str();
        let header: Vec<u8> = header.into_bytes();
        let header: String = base64::encode(header);
        header
    }

    /// Decodes an `input` `String` into a JOSE header. `input` must be a valid encoded JWT
    /// payload, elsewise a `JWTError` will be thrown.
    pub fn decode_b64(input: &str) -> err::Result<JWTHeader> {
        let header: err::Result<Value> =
            // (1) String of b64 chars -> Vec<u8>, a sequence of octets. A DecodeError is thrown
            // if a byte is found to be out of range.
            base64::decode(&input)
            .map_err(|e| { err::JWTError::ParseError(format!("{}", e)) })
            // (2) Vec<u8> -> String. Recall that Strings are utf-8.
            .and_then(|inner| { 
                String::from_utf8(inner)
                .map_err(|e| { err::JWTError::ParseError(format!("{}", e)) })
            })
            // (3) String -> JSON.
            .and_then(|inner| {
                serde_json::from_str(&inner)
                .map_err(|e| { err::JWTError::ParseError(format!("{}", e)) })
            });
        // Early return to unpack the non-error header.
        let header: Value = match header {
            Ok(header) => header,
            Err(e) => return Err(e)
        };

        let alg = &header["alg"];
        if alg.is_null() {
            return Err(err::JWTError::SchemaError)
        }
        let alg = alg.as_str().unwrap();
        let alg = match alg {
            "none" => Alg::None,
            _ => return Err(err::JWTError::NotImplementedError)
        };
        Ok(JWTHeader {
            alg, cty: Cty::None, typ: Typ::None
        })
    }
}

impl fmt::Display for JWTHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.encode_str())
    }
}