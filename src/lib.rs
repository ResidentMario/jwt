//! `jwt` is a JWT parsing Rust crate I implemented in order to gain experience with Rust.
//!
//! **Important note**: a JWS may contain an arbitrary octet sequence as its payload. This library
//! restricts the space of valid JWS payloads to just valid JSON objects (which matches the JWT
//! specification).
//!
//! Also, we only currently use (encode into and decode from) the compact JWS format.

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
/// The `JWT` struct represents a JWT of any of three valid types: an unencrypted JWT, a JWS (JSON
/// Web Signature), or a JWE (JSON Web Encryption). This struct and the methods that interact with
/// it form the bulk of the public-facing API.
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
pub struct JWT {
    pub header: header::JWTHeader,
    pub claim_set: claims::ClaimSet,
}

impl traits::JsonSerializable for JWT {
    /// Encodes self into a plaintext string suitable for display.
    fn encode_str(&self) -> String {
        // Otherwise this is a JWS.
        match self.header.alg {
            header::Alg::None =>
                self.header.encode_str() + "\n.\n" + &self.claim_set.encode_str() + "\n.\n",
            header::Alg::HS256 => {
                let signature_plaintext: String =
                    self.header.encode_b64() + "." + &self.claim_set.encode_b64();
                // TODO: apply the encoding here.
                let signature_plaintext = "HELLO";

                self.header.encode_str() + "\n.\n" + &self.claim_set.encode_str() + "\n.\n" +
                &signature_plaintext
            },
        }
    }

    /// Encodes self into a base64-encoded JWT string suitable for transport.
    fn encode_b64(&self) -> String {
        self.header.encode_b64() + "\n.\n" +
        &base64::encode(self.claim_set.encode_str().into_bytes()) +
        "\n.\n"
    }

    /// Decodes an `input` base64-encoded `String` into a JWT. `input` must be a valid encoded JWT
    /// payload, otherwise a `JWTError` will be returned.
    fn decode_b64(input: &str) -> err::Result<JWT> {
        let components = JWT::split_into_components(input);
        let components = match components {
            Ok(components) => components,
            Err(e) => return Err(e),
        };

        let header = header::JWTHeader::decode_b64(&components[0]);
        let header: header::JWTHeader = match header {
            Ok(header) => header,
            Err(e) => return Err(e),
        };

        let claim_set = claims::ClaimSet::decode_b64(&components[1]);
        let claim_set: claims::ClaimSet = match claim_set {
            Ok(claim_set) => claim_set,
            Err(e) => return Err(e),
        };

        let mut jwt = JWT::new();
        jwt.header = header;
        jwt.claim_set = claim_set;
        Ok(jwt)
    }

    /// Decodes an `input` plaintext JWT `String` into a `JWT`. `input` must be a valid JWT
    /// payload, otherwise a `JWTError` will be returned.
    fn decode_str(input: &str) -> err::Result<JWT> {
        let components = JWT::split_into_components(input);
        let components = match components {
            Ok(components) => components,
            Err(e) => return Err(e),
        };

        let header = header::JWTHeader::decode_str(&components[0]);
        let header: header::JWTHeader = match header {
            Ok(header) => header,
            Err(e) => return Err(e),
        };

        let claim_set = claims::ClaimSet::decode_str(&components[1]);
        let claim_set: claims::ClaimSet = match claim_set {
            Ok(claim_set) => claim_set,
            Err(e) => return Err(e),
        };

        let mut jwt = JWT::new();
        jwt.header = header;
        jwt.claim_set = claim_set;
        Ok(jwt)
    }
}

impl JWT {
    // Splits a base64-encoded or plaintext JWT into its three components, removing optional
    // characters (space, CR, LF) in the process.
    fn split_into_components(input: &str) -> err::Result<Vec<String>> {
        let filter = |c: &char| -> bool { 
            c != &'\u{0020}' && c != &'\u{000A}' && c != &'\u{000D}'
        };
        let components = input
            .split(".")
            .map(|s: &str| s.chars().filter(filter).collect::<String>())
            .collect::<Vec<String>>();
        if components.len() != 3 {
            return Err(err::JWTError::SchemaError)
        }
        Ok(components)
    }

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
}
