//! `jwt` is a JWT parsing Rust crate I implemented in order to gain experience with Rust.

use std::fmt;

// "[pub] mod NAME;" in lib.rs tells Rust to import a namespace from a file in the same crate.
// In other files, this is a bit different: this will import from the such-named _directory_;
// you want "use crate::err;" to import from other files in the same directory.
pub mod err;
pub mod header;
pub mod claims;
pub mod traits;

pub use traits::JsonSerializable;

#[derive(Debug)]
pub struct JWT {
    pub header: header::JWTHeader,
    pub claim_set: claims::ClaimSet,
}

/// The `JWT` struct represents a JWT of any of three valid types: unencrypted JWT, JWS (JSON Web
/// Signature), or JWE (JSON Web Encryption). This struct and the methods that interact with it
/// form the bulk of the public-facing API.
///
/// # Examples
///
/// ```
/// use jwt::JWT;
/// use jwt::JsonSerializable;
///
/// // Encode and decode a simple unecrypted `JWT` to and from a plaintext `String`.
/// let jwt: JWT = JWT::from_plain_str("{\"foo\": \"bar\"}").unwrap();
/// let jwt_as_plaintext: String = jwt.encode_str();
/// assert_eq!(r#"{"alg": "none"}
/// .
/// {"foo":"bar"}
/// .
/// "#, jwt_as_plaintext);
///
/// // Encode and decode to and from an unencrypted base64 `String`.
/// let jwt_encoded: String = jwt.encode_b64();
/// assert_eq!(r#"eyJhbGciOiAibm9uZSJ9
/// .
/// eyJmb28iOiJiYXIifQ==
/// .
/// "#, jwt_encoded);
/// let jwt: JWT = JWT::decode_b64(&jwt_encoded).unwrap();
/// ```
impl traits::JsonSerializable for JWT {
    /// Encodes self into a plaintext string suitable for display.
    fn encode_str(&self) -> String {
        self.header.encode_str() + "\n.\n" + &self.claim_set.encode_str() + "\n.\n"
    }

    /// Encodes self into a base64-encoded JWT string suitable for transport.
    fn encode_b64(&self) -> String {
        self.header.encode_b64() + "\n.\n" +
        &base64::encode(self.claim_set.encode_str().into_bytes()) +
        "\n.\n"
    }

    // fn decode_str(input: &str) -> err::Result<JWT> {
    //     // Before we can operate on the component strings, we have to strip out {space, CR, LF}
    //     // characters.
    //     let filter = |c: &char| -> bool { 
    //         c != &'\u{0020}' && c != &'\u{000A}' && c != &'\u{000D}'
    //     };
    //     let components = input
    //         .split(".")
    //         .map(|s: &str| s.chars().filter(filter).collect::<String>())
    //         .collect::<Vec<String>>();
    // }

    /// Decodes an `input` base64-encoded `String` into a JWT. `input` must be a valid encoded JWT
    /// payload, otherwise a `JWTError` will be returned.
    fn decode_b64(input: &str) -> err::Result<JWT> {
        // NOTE: splitting on the "." character leaves in {space, CR, LF} code points. We need to
        // remove these code points *before* passing this data to base64::decode.
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

        let header = header::JWTHeader::decode_b64(&components[0]);
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

    // TODO: implement this
    fn decode_str(input: &str) -> err::Result<JWT> {
        Ok(JWT::new())
    }

    // /// Decodes an `input` base64 encoded `String` into a JWT. `input` must be a valid encoded
    // /// JWT payload, otherwise a `JWTError` will be thrown.
    // fn decode_b64(input: &str) -> err::Result<JWT> {
    //     base64::decode(input)
    //         .map_err(|e| { err::JWTError::ParseError(format!("{}", e)) })
    //         .and_then(|inner| {
    //             String::from_utf8(inner)
    //             .map_err(|e| { err::JWTError::ParseError(format!("{}", e)) })
    //         })
    //         .and_then( |inner| { JWT::decode_str(&inner) })
    // }
}

impl JWT {
    /// Outputs an unsecured `JWT` containing the given `claims_set`, or a `JWTError` if the
    /// `claims_set` is invalid. Takes a plaintext `JWT` string as input.
    pub fn from_plain_str(claims_set: &str) -> err::Result<JWT> {
        claims::ClaimSet::decode_str(claims_set)
            .map(|claims_set| { 
                JWT {
                    header: header::JWTHeader {
                        typ: header::Typ::None,
                        alg: header::Alg::None,
                        cty: header::Cty::None
                    },
                    claim_set: claims_set
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
            claim_set: claims::ClaimSet::new()
        }
    }
}

impl fmt::Display for JWT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.encode_str())
    }
}

#[cfg(test)]
mod tests {
    // Tests are isolated to their own mod, so they do not have any imports by default.
    //
    // Useful trick for importing everything from the current file's context, which for the tests,
    // is the parent context, is to use super.
    use super::*;

    #[test]
    fn test_encode_empty() {
        let jwt = JWT::new();
        assert_eq!(r#"eyJhbGciOiAibm9uZSJ9
.
e30=
.
"#, jwt.encode_b64());
    }

    #[test]
    fn test_encode_nonempty() {
        let mut jwt = JWT::new();
        jwt.claim_set = claims::ClaimSet::decode_str("{\"foo\":\"bar\"}").unwrap();
        assert_eq!(r#"eyJhbGciOiAibm9uZSJ9
.
eyJmb28iOiJiYXIifQ==
.
"#, jwt.encode_b64());
    }

    #[test]
    fn test_encode_str_empty() {
        let jwt = JWT::new();
        assert_eq!(r#"{"alg": "none"}
.
{}
.
"#, jwt.encode_str());
    }

    #[test]
    fn test_encode_str_nonempty() {
        let mut jwt = JWT::new();
        jwt.claim_set = claims::ClaimSet::decode_str("{\"foo\":\"bar\"}").unwrap();
        assert_eq!(r#"{"alg": "none"}
.
{"foo":"bar"}
.
"#, jwt.encode_str());
    }

//     #[test]
//     fn test_decode_str() {
//         let raw = r#"{"alg": "none"}
// .
// {"foo":"bar"}
// .
// "#;
//         let jwt = JWT::decode_b64(raw).unwrap();
//         assert_eq!(jwt.encode_str(), raw);
//     }
}
