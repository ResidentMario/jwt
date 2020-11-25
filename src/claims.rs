use std::fmt;
use std::collections::HashMap;
use url::{Url};
use serde_json::{Map, Value};

use crate::err;

#[derive(Debug)]
/// The JWT specification states that claim names must be legal `StringOrURI` values. For names
/// lacking a colon `:`, a `StringOrURI` is a (valid UTF-8) string. For names containing a colon,
/// a `StringOrURI` is a `URI`, and is expected to follow the `URI` schema.
///
/// # Examples
/// ```
/// use jwt::claims::StringOrURI;
///
/// // Construct a String type StringOrURI.
/// let s = StringOrURI::parse(String::from("foo")).unwrap();
/// assert!(matches!(s, StringOrURI::String(_)));
///
/// // Construct a URI type StringOrURI.
/// let s = StringOrURI::parse(String::from("foo:bar")).unwrap();
/// assert!(matches!(s, StringOrURI::URI(_)));
/// ```
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
    /// Constructs a new empty string type `StringOrURI`.
    pub fn new_string() -> StringOrURI { StringOrURI::String(String::from("")) }
    /// Constructs a new URI type `StringOrURI` with contents `foo:bar` (an example minimal legal
    /// URI string that satisfies the JWT URI condition that it must contain a colon).
    pub fn new_uri() -> StringOrURI { StringOrURI::URI(String::from("foo:bar")) }

    /// Parses a string into a new `StringOrURI` value. Returns an `err::JWTError::ParseError` if
    /// the string could not be parsed; this should only happen if the string contains a colon `:`,
    /// indicating that it is a URI, but it fails to parse as one.
    pub fn parse(inp: String) -> err::Result<StringOrURI> {
        if inp.contains(":") {
            Url::parse(&inp)
                .map(|inner| { StringOrURI::URI(String::from(inner.as_str())) })
                .map_err(|e| { err::JWTError::ParseError(format!("{}", e)) })
        } else {
            Ok(StringOrURI::String(inp))
        }
    }

    /// Converts the `StringOrURI` to a string and returns.
    pub fn as_str(&self) -> &str {
        match self {
            StringOrURI::String(value) => value,
            StringOrURI::URI(value) => value,
        }
    }
}

#[derive(Debug)]
/// Claims fall into one of three types.
///
/// **Registered claims** are those which have been formally registered with the IETF, and are
/// reserved for that use everywhere. [This list](https://www.iana.org/assignments/jwt/jwt.xhtml)
/// consists of a small set that was introduced alongside the RFC, and a few dozen other names
/// that have been registered since. Examples include `iss` (issuer) and `sub` (subject).
///
/// **Public claims** are claim names containing a *collision-resistant name* (e.g. a claim name
/// with a random hash component), which makes them safe for consumption by external APIs which
/// may insert their own application-independent claims into the JWT payload.
///
/// **Private claims** are non-registered, non-collision-resistant names. It is up to the APIs
/// producing and consuming the claim to agree on the meaning and uniqueness of the name. In
/// practice, most claims are private.
pub enum ClaimType {
    Registered,
    Public,
    Private,
}

#[derive(Debug)]
/// A **claim** is a statement of fact, consisting of a *claim name* (a `StringOrURI`) and a
/// *claim value* (an arbitrary JSON fragment). A set of claims (a `ClaimSet`) composes the
/// payload of a JWT.
///
/// # Examples
/// ```
/// use jwt::claims::{Claim, ClaimType};
/// use serde_json;
///
/// // Construct a simple claim.
/// let c = Claim::parse(
///     String::from("some_claim_name"),
///     serde_json::json!("some_claim_value")
/// ).unwrap();
/// assert!(matches!(c.claim_type, ClaimType::Private));
///
/// // Construct a claim using a registered claim name.
/// let c = Claim::parse(String::from("iss"), serde_json::json!("Bob")).unwrap();
/// assert!(matches!(c.claim_type, ClaimType::Registered));
/// ```
pub struct Claim {
    pub claim_type: ClaimType,
    pub claim_name: StringOrURI,
    pub claim_value: Value,
}

impl fmt::Display for Claim {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
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
    pub fn parse(claim_name: String, claim_value: Value) -> err::Result<Claim> {
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

    /// Returns the `Claim` in string format.
    pub fn as_str(&self) -> String {
        // TODO: why can this fail? Investigate why unwrap is necessary here.
        String::from("{\"") + self.claim_name.as_str() + "\":" +
        &serde_json::to_string(&self.claim_value).unwrap() + "}"
    }
}

#[derive(Debug)]
/// A **ClaimSet** is a set of (uniquely named) claims. It is the payload portion of a complete
/// `JWT`.
///
/// Internally, `ClaimSet` uses a `HashMap` to provide `O(1)` lookups and `O(1)` (amortized)
/// inserts of individual `Claim` key-value pairs.
///
/// Note that, according to RFC 7519, it is the choice of the implementation whether or not to
/// enforce that JWT claims have unique names. We chose to enforce the constraint that they do.
///
/// # Examples
/// ```
/// use jwt::claims::ClaimSet;
///
/// // Construct a ClaimSet
/// let cs_str = "{\"claim_name\": \"claim_value\", \"another_claim_name\": \"another_claim_value\"}";
/// let cs = ClaimSet::from_str(cs_str).unwrap();
///
/// // Transform it back into a string. Notice that order is *not* preserved.
/// println!("{}", cs.as_str())
/// // {"another_claim_name": "another_claim_value", "claim_name": "claim_value"}
/// ```
pub struct ClaimSet {
    pub claims: HashMap<String, Claim>,
}

impl fmt::Display for ClaimSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl ClaimSet {
    /// Creates an empty `ClaimSet`.
    pub fn new() -> ClaimSet {
        ClaimSet{ claims: HashMap::<String, Claim>::new() }
    }

    /// Inserts a `Claim` into the `ClaimSet`. Note that this method takes ownership of the
    /// `Claim`.
    pub fn insert(&mut self, claim: Claim) -> err::Result<()> {
        let claim_name_str = claim.claim_name.as_str();
        if self.claims.contains_key(claim_name_str) {
            return err::Result::<()>::Err(err::JWTError::SchemaError)
        } else {
            self.claims.insert(String::from(claim_name_str), claim);
            Ok(())
        }
    }

    /// Constructs a new `ClaimSet` from a valid JSON string of key-value pairs. Returns a
    /// `err::JWTError::ParseError` if the input string is not valid JSON.
    pub fn from_str(claim_set: &str) -> err::Result<ClaimSet> {
        let parse: err::Result<Map<String, serde_json::Value>> =
            serde_json::from_str(&claim_set)
            .map_err(|e| { err::JWTError::ParseError(format!("{}", e)) });

        // Early return to unpack the parse error.
        let parse = match parse {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        let mut result = ClaimSet::new();
        for claim_name in parse.keys() {
            // Using unwrap here is fine because this is a safe operation.
            let claim_value = parse.get(claim_name).unwrap();

            // Early return to work around a potential URI parse error.
            // Q: Why is clone necessary here?
            // A: claim_name and claim_value are pointer references to data owned by the parse
            //    value reference. We cannot dereference them because doing so would be a Move
            //    that invalidates the parse value reference, which is not legal to do here
            //    because we are inside a parse.keys() iterator. Since we have another live
            //    reference that a deference would implicitly destroy, the dereference is
            //    forbidden.
            //
            //    There may be a more clever way to handle this situation, but a clone() is an
            //    easy workaround for right now.
            let claim = Claim::parse(claim_name.clone(), claim_value.clone());
            let claim = match claim {
                Ok(claim) => claim,
                Err(e) => return Err(e)
            };

            match result.insert(claim) {
                Err(e) => return Err(e),
                _ => ()
            }
        };
        Ok(result)
    }

    /// Returns the `Claim` with the given name from the `ClaimSet`, or a
    /// `err::JWTError::SchemaError` if none is found.
    pub fn get(&self, claim_name: &str) -> err::Result<&Claim> {
        self.claims.get(claim_name).ok_or(err::JWTError::SchemaError)
    }

    /// Returns the `ClaimSet` in `String` format.
    pub fn as_str(&self) -> String {
        if self.claims.len() == 0 {
            return String::from("{}")
        }

        let mut out_parts: Vec<String> = vec![String::from("{")];
        for claim_name in self.claims.keys() {
            // Operation is safe, hence unwrap().
            let claim = self.claims.get(claim_name).unwrap();
            let claim = claim.as_str();
            out_parts.push(String::from(&claim[1..(claim.len() - 1)]));
            out_parts.push(String::from(","));
        }
        out_parts.pop();
        out_parts.push(String::from("}"));
        out_parts.join("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stringoruri_string() {
        let s = StringOrURI::parse(String::from("foo")).unwrap();
        assert!(matches!(s, StringOrURI::String(_)));
        assert_eq!(s.as_str(), "foo");
    }

    #[test]
    fn test_stringoruri_uri() {
        let s = StringOrURI::parse(String::from("foo:bar")).unwrap();
        assert!(matches!(s, StringOrURI::URI(_)));
        assert_eq!(s.as_str(), "foo:bar");
    }

    #[test]
    fn test_claim_registered() {
        let c = Claim::parse(
            String::from("iss"), 
            serde_json::json!("{foo:bar}")
        ).unwrap();
        assert_eq!(c.claim_value, "{foo:bar}");
        assert!(matches!(c.claim_type, ClaimType::Registered));
    }

    #[test]
    fn test_claim_public_uri() {
        let c = Claim::parse(
            String::from("foo:bar"), 
            serde_json::json!("{bar:baz}")
        ).unwrap();
        assert_eq!(c.claim_value, "{bar:baz}");
        assert!(matches!(c.claim_type, ClaimType::Public));
    }

    #[test]
    fn test_claim_private() {
        let c = Claim::parse(
            String::from("foo"), 
            serde_json::json!("{bar:baz}")
        ).unwrap();
        assert_eq!(c.claim_value, "{bar:baz}");
        assert!(matches!(c.claim_type, ClaimType::Private));
    }

    #[test]
    fn test_claim_set() {
        let c = ClaimSet::from_str("{\"a\": \"b\"}").unwrap();
        assert_eq!(c.claims.get("a").unwrap().claim_value, "b");
    }
}

// TODO:
// Next step is implementing the reserved claims from the RFC, and the public claims from
// https://www.iana.org/assignments/jwt/jwt.xhtml (ocassionally updating). Plus, the ability to
// declare your own public claim name, with a selection of collision-resistant algorithms for
// generating public claim names. And finally, private names.