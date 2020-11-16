use serde_json::Value;
use std::{error::Error, fmt, result};

#[derive(Debug)]
pub enum JWTError {
    ParseError(String),
    SchemaError,
    NotImplementedError
}

// Q: why is this allowed to be empty?
// A: the Error trait has description, cause, and source methods. These have default
// implementations, which we can trigger by leaving the impl block empty.
//
// On the other hand, Error _also_ requires implementing the fmt::Display and Debug supertraits.
// The Debug supertrait is usually implemented using derive, as above. The fmt::Display supertrait
// we implement ourselves here.
//
// Cf https://stackoverflow.com/questions/42584368/how-do-you-define-custom-error-types-in-rust
impl Error for JWTError {}
impl fmt::Display for JWTError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            JWTError::ParseError(e) => {
                write!(f, "Invalid JSON, parsing failed with:\n{}", e)
            },
            JWTError::SchemaError => {
                write!(f, "Schema error!")
            }
            JWTError::NotImplementedError => {
                write!(f, "Not implemented.")
            }
        }
    }
}
// Result aliasing is a common technique for managing the type of errors specific to your library.
// Cf https://blog.burntsushi.net/rust-error-handling/#the-result-type-alias-idiom
pub type Result<T> = result::Result<T, JWTError>;

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

#[derive(Debug)]
pub struct JWT {
    pub header: JWTHeader,
    pub claims_set: Value,
}

impl JWTHeader {
    pub fn encode_str(&self) -> String {
        // Q: why is to_owned necessary here?
        //
        // A: A variable lives on the stack, so the size of its contents must be known at compile
        // time. A str is unsized, so "{alg" creates a &str pointer, which does not have ownership
        // over the string contents.
        //
        // A String, meanwhile, _is_ sized, and therefore returns an owned reference. One can
        // convert an &str to a String using to_owned.
        //
        // An alternative would be using String::new.
        String::from("{\"alg\": ") + "\"none\"" + "}"
    }

    pub fn encode(&self) -> String {
        // Q: why doesn't the following code work?
        //
        // let mut header: String = "{alg: ".to_owned();
        // header.as_bytes()
        //
        // A: header is an owned reference scoped to the function closure. as_bytes returns a
        // borrow of this reference, which goes out of scope once the function finishes executing,
        // which is illegal.
        //
        // The fix is to use into_bytes() instead.
        //
        // Q: Why doesn't the following code work?
        //
        // let header: String = self.encode_str();
        // let header = header.into_bytes()[..];
        // header
        //
        // A: the [..] operator takes a slice of the vector. A vector is an owned reference. A
        // slice is a borrow. Therefore, we are in the same position we were in before: the slice
        // reference is illegal because it is a borrow of a variable that went out of scope.
        let header: String = self.encode_str();
        let header: Vec<u8> = header.into_bytes();
        let header: String = base64::encode(header);
        header
    }

    pub fn decode_str(input: &str) -> Result<JWTHeader> {
        let header: Result<Value> =
            // (1) String of b64 chars -> Vec<u8>, a sequence of octets. A DecodeError is thrown
            // if a byte is found to be out of range.
            base64::decode(&input)
            .map_err(|e| { JWTError::ParseError(format!("{}", e)) })
            // (2) Vec<u8> -> String. Recall that Strings are utf-8.
            .and_then(|inner| { 
                String::from_utf8(inner)
                .map_err(|e| { JWTError::ParseError(format!("{}", e)) })
            })
            // (3) String -> JSON.
            .and_then(|inner| {
                serde_json::from_str(&inner)
                .map_err(|e| { JWTError::ParseError(format!("{}", e)) })
            });
        // Early return to unpack the non-error header.
        let header: Value = match header {
            Ok(header) => header,
            Err(e) => return Err(e)
        };

        let alg = &header["alg"];
        if alg.is_null() {
            return Err(JWTError::SchemaError)
        }
        let alg = alg.as_str().unwrap();
        let alg = match alg {
            "none" => Alg::None,
            _ => return Err(JWTError::NotImplementedError)
        };
        Ok(JWTHeader {
            alg, cty: Cty::None, typ: Typ::None
        })
    }
}

impl JWT {
    pub fn encode_str(&self) -> String {
        self.header.encode_str() + "\n.\n" + &self.claims_set.to_string() + "\n.\n"
    }

    pub fn encode(&self) -> String {
        self.header.encode() + "\n.\n" +
        &base64::encode(self.claims_set.to_string().into_bytes()) +
        "\n.\n"
    }

    pub fn decode_str(input: String) -> Result<JWT> {
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
            return Result::<JWT>::Err(JWTError::SchemaError)
        }

        let header = JWTHeader::decode_str(&components[0]);
        let header: JWTHeader = match header {
            Ok(header) => header,
            Err(e) => return Err(e)
        };

        let claims_set: Result<JWT> =
            // (1) String of b64 chars -> Vec<u8>, a sequence of octets. A DecodeError is thrown
            // if a byte is found to be out of range.
            base64::decode(&components[1])
            .map_err(|e| { JWTError::ParseError(format!("{}", e)) })
            // (2) Vec<u8> -> String. Recall that Strings are utf-8.
            .and_then(|inner| { 
                String::from_utf8(inner)
                .map_err(|e| { JWTError::ParseError(format!("{}", e)) })
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
        Result::<JWT>::Ok(jwt)
    }

    pub fn from_plain_str(claims_set: &str) -> Result<JWT> {
        serde_json::from_str(claims_set)
            .map(|claims_set| { 
                JWT {
                    header: JWTHeader{typ:Typ::None, alg:Alg::None, cty:Cty::None},
                    claims_set
                }
            })
            .map_err(|e| { JWTError::ParseError(format!("{}", e)) })
    }

    pub fn new() -> JWT {
        JWT {
            header: JWTHeader{typ:Typ::None, alg:Alg::None, cty:Cty::None},
            claims_set: serde_json::json!("{}")
        }
    }
}
