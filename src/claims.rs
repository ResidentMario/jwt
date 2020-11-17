// use serde_json::Value;
use std::fmt;
use url::{Url};
use serde_json::Value;

use crate::err;

#[derive(Debug)]
enum StringOrURI {
    String(String),
    URI(String),
}

impl fmt::Display for StringOrURI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StringOrURI::String(value) => write!(f, "String({})", value),
            StringOrURI::URI(value) => write!(f, "URI({})", value),
        }
    }
}

impl StringOrURI {
    fn new_string() -> StringOrURI { StringOrURI::String(String::from("")) }
    fn new_uri() -> StringOrURI { StringOrURI::URI(String::from("")) }
    
    fn parse(inp: String) -> err::Result<StringOrURI> {
        if inp.contains(":") {
            Url::parse(&inp)
                .map(|inner| { StringOrURI::URI(String::from(inner.as_str())) })
                .map_err(|e| { err::JWTError::ParseError(format!("{}", e)) })
        } else {
            Ok(StringOrURI::String(inp))
        }
    }
}

#[derive(Debug)]
enum ClaimType {
    Registered,
    Public,
    Private,
}

// let reserved_claims = vec!["12"];

// TODO: implement Format trait
#[derive(Debug)]
pub struct Claim {
    claim_type: ClaimType,
    claim_name: String,
    claim_value: Value,
}

impl Claim {
    pub fn new() -> Claim {
        Claim { 
            claim_type: ClaimType::Private,
            claim_name: String::from(""),
            claim_value: serde_json::json!({}),
        }
    }

    pub fn from_str(claim_name: String, claim_value: Value) -> Claim {
        Claim::new()
    }
}

// TODO:
// Next step is implementing the reserved claims from the RFC, and the public claims from
// https://www.iana.org/assignments/jwt/jwt.xhtml (ocassionally updating). Plus, the ability to
// declare your own public claim name, with a selection of collision-resistant algorithms for
// generating public claim names. And finally, private names.