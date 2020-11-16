//! `jwt` is a JWT parsing Rust crate I implemented in order to gain experience with Rust.

use serde_json::Value;
use std::fmt;

// "[pub] mod NAME;" in lib.rs tells Rust to import a namespace from a file in the same crate.
// In other files, this is a bit different: this will import from the such-named _directory_;
// you want "use crate::err;" to import from other files in the same directory.
pub mod err;
pub mod header;

#[derive(Debug)]
pub struct JWT {
    pub header: header::JWTHeader,
    pub claims_set: Value,
}

impl JWT {
    /// Encodes self into a plaintext string suitable for display.
    pub fn encode_str(&self) -> String {
        self.header.encode_str() + "\n.\n" + &self.claims_set.to_string() + "\n.\n"
    }

    /// Encodes self into a base64-encoded JWT string suitable for transport.
    pub fn encode(&self) -> String {
        self.header.encode() + "\n.\n" +
        &base64::encode(self.claims_set.to_string().into_bytes()) +
        "\n.\n"
    }

    /// Decodes an `input` `String` into a JWT. `input` must be a valid encoded JWT payload,
    /// elsewise a `JWTError` will be thrown.
    pub fn decode_str(input: &str) -> err::Result<JWT> {
        // Before we can operate on the component strings, we have to strip out {space, CR, LF}
        // characters.
        let filter = |c: &char| -> bool { 
            c != &'\u{0020}' && c != &'\u{000A}' && c != &'\u{000D}'
        };
        let components = input
            .split(".")
            .map(|s: &str| s.chars().filter(filter).collect::<String>())
            .collect::<Vec<String>>();
        if components.len() != 3 {
            return err::Result::<JWT>::Err(err::JWTError::SchemaError)
        }

        let header = header::JWTHeader::decode_str(&components[0]);
        let header: header::JWTHeader = match header {
            Ok(header) => header,
            Err(e) => return Err(e)
        };

        let claims_set: err::Result<JWT> =
            // (1) String of b64 chars -> Vec<u8>, a sequence of octets. A DecodeError is thrown
            // if a byte is found to be out of range.
            base64::decode(&components[1])
            .map_err(|e| { err::JWTError::ParseError(format!("{}", e)) })
            // (2) Vec<u8> -> String. Recall that Strings are utf-8.
            .and_then(|inner| { 
                String::from_utf8(inner)
                .map_err(|e| { err::JWTError::ParseError(format!("{}", e)) })
            })
            //(3) String -> JWT (via from_plain_str).
            // NOTE: this will need to change once we start implementing JWS and JWE.
            .and_then( |inner| { JWT::from_plain_str(&inner) });

        // Early return to unpack the non-error JWT.
        let mut jwt: JWT = match claims_set {
            Ok(claims_set) => claims_set,
            Err(e) => return Err(e)
        };
        jwt.header = header;
        err::Result::<JWT>::Ok(jwt)
    }

    /// Outputs an unsecured JWT containing the given `claims_set`, or a `JWTError` if the
    /// `claims_set` is invalid. Takes a plaintext JWT string as input.
    pub fn from_plain_str(claims_set: &str) -> err::Result<JWT> {
        serde_json::from_str(claims_set)
            .map(|claims_set| { 
                JWT {
                    header: header::JWTHeader {
                        typ: header::Typ::None,
                        alg: header::Alg::None,
                        cty: header::Cty::None
                    },
                    claims_set
                }
            })
            .map_err(|e| { err::JWTError::ParseError(format!("{}", e)) })
    }

    /// Constructor. Outputs an empty unsecured JWT.
    pub fn new() -> JWT {
        JWT {
            header: header::JWTHeader {
                typ: header::Typ::None,
                alg: header::Alg::None,
                cty: header::Cty::None
            },
            claims_set: serde_json::json!("{}")
        }
    }
}

impl fmt::Display for JWT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.encode_str())
    }
}
