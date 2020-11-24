use std::fmt;
use std::collections::HashMap;
use url::{Url};
use serde_json::Value;

use crate::err;

#[derive(Debug)]
/// The JWT specification states that claim names must be legal StringOrURI values. For names
/// lacking a colon (":"), a StringOrURI is a (valid UTF-8) string. For names containing a colon,
/// a StringOrURI is a URI, and is expected to follow the URI schema.
pub enum StringOrURI {
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
    /// Constructs a new empty string type StringOrURI.
    fn new_string() -> StringOrURI { StringOrURI::String(String::from("")) }
    /// Constructs a new URI type StringOrURI with contents "foo:bar" (an example minimal legal
    /// URI string that satisfies the JWT URI condition that it must contain a colon (":").
    fn new_uri() -> StringOrURI { StringOrURI::URI(String::from("foo:bar")) }

    /// Parses a string into a new StringOrURI value.
    fn parse(inp: String) -> err::Result<StringOrURI> {
        if inp.contains(":") {
            Url::parse(&inp)
                .map(|inner| { StringOrURI::URI(String::from(inner.as_str())) })
                .map_err(|e| { err::JWTError::ParseError(format!("{}", e)) })
        } else {
            Ok(StringOrURI::String(inp))
        }
    }

    /// Converts to a string and returns.
    fn as_str(&self) -> &str {
        match self {
            StringOrURI::String(value) => value,
            StringOrURI::URI(value) => value,
        }
    }
}

#[derive(Debug)]
/// Claims fall into one of three types. Registered claims are those which have been formally
/// registered with the IETF, and are reserved for that use everywhere. This list consists of
/// a small set that was introduced alongside the RFC, and a few dozen other names that have
/// been registered since. Public types are claim names containing a collision-resistant name,
/// which makes them "safe for public consumption". Finally, private names do *not* implement
/// a collision-resistant name, which makes interpeting them a function of the private API.
pub enum ClaimType {
    Registered,
    Public,
    Private,
}

// TODO: implement Format trait
#[derive(Debug)]
/// A claim is a key-value pair where the key is the claim name and the value, the claim vaue.
/// A claim also has a type: registered, public, or private. Refer to the docstring for ClaimType,
/// or to the RFC, for details.
pub struct Claim {
    pub claim_type: ClaimType,
    pub claim_name: StringOrURI,
    pub claim_value: Value,
}

const REGISTERED_CLAIMS: &[&str; 7] = &["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

impl Claim {
    /// Constructs a new (empty) private claim.
    pub fn new() -> Claim {
        Claim { 
            claim_type: ClaimType::Private,
            claim_name: StringOrURI::new_string(),
            claim_value: serde_json::json!({}),
        }
    }

    fn get_claim_type(claim_name: &StringOrURI) -> ClaimType {
        match claim_name {
            // Assume that any URIs the user passes are collision-resistant.
            StringOrURI::URI(_) => ClaimType::Public,
            StringOrURI::String(s) => {
                // contains is compare-by-value.
                if (*REGISTERED_CLAIMS).contains(&s.as_str()) {
                    ClaimType::Registered
                } else {
                    ClaimType::Private
                }
            }
        }
    }

    /// Constructs a new claim from an input string.
    pub fn from_str(claim_name: String, claim_value: Value) -> err::Result<Claim> {
        let mut claim = Claim::new();

        // Early return to unpack the non-error header.
        let claim_name: StringOrURI = match StringOrURI::parse(claim_name) {
            Ok(claim_name) => claim_name,
            Err(e) => return Err(e)
        };

        claim.claim_name = claim_name;
        claim.claim_type = Claim::get_claim_type(&claim.claim_name);
        claim.claim_value = claim_value;
        Ok(claim)
    }
}

/// The set of claim names and their associated claim value payloads compose the claim set.
/// According to the RFC, it is the choice of the implementer whether or not to consider JWTs with
/// multiple copies of the same field invalid, or to populate with the last field and discard the
/// rest.
///
/// In this implementation, we will enforce claim name uniqueness. The ClaimSet object is
/// responsible for (1) enforcing claim name uniqueness and (2) providing fast lookups.
///
/// I've chosen to duplicate the claim name to the hash map key to provide O(1) lookup of claim
/// names by key. This means duplicating the claim name (once in the ClaimSet key, and once in the
/// Claim object) but this is fine, in my opinion. JWTs are supposed to be small, so duplicating
/// the string to get O(1) get performance (over the alternative - searching a list) is fine.
pub struct ClaimSet {
    pub claims: HashMap<String, Claim>,
}

impl fmt::Display for ClaimSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: implement this properly.
        write!(f, "ClaimSet(TODO)")
    }
}

impl ClaimSet {
    /// Creates an empty ClaimSet
    pub fn new() -> ClaimSet {
        ClaimSet{ claims: HashMap::<String, Claim>::new() }
    }

    /// Inserts a claim into the ClaimSet, consuming the claim in the process.
    pub fn insert(&mut self, claim: Claim) -> err::Result<()> {
        let claim_name_str = claim.claim_name.as_str();
        if self.claims.contains_key(claim_name_str) {
            return err::Result::<()>::Err(err::JWTError::SchemaError)
        } else {
            self.claims.insert(String::from(claim_name_str), claim);
            Ok(())
        }
    }

    /// Returns the Claim with the given name from the ClaimSet, or a SchemaError if none is
    /// found.
    pub fn get(&mut self, claim_name: &str) -> err::Result<&Claim> {
        self.claims.get(claim_name).ok_or(err::JWTError::SchemaError)
    }
}

// TODO:
// Next step is implementing the reserved claims from the RFC, and the public claims from
// https://www.iana.org/assignments/jwt/jwt.xhtml (ocassionally updating). Plus, the ability to
// declare your own public claim name, with a selection of collision-resistant algorithms for
// generating public claim names. And finally, private names.