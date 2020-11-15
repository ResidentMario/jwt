use serde_json::Value;
use std::{error::Error, fmt, result};

#[derive(Debug)]
pub enum JWTError {
    ParseError(serde_json::Error),
    SchemaError
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

        let header = match base64::decode(&components[0]) {
            Ok(inner) => {
                // Q: what is all this???
                //
                // A: well, the output of base64::decode is a Result enum containing a Vec<u8>
                // (if the decode succeeded; an Error if it did not). To convert this to a
                // String, we must use one of from_utf8, an associated method with its own error
                // handler, or the "lazy" from_ut8_lossy, an associated method lacking an error
                // handler.
                //
                // These methods take a slice reference, _not_ a Vec, as input. And they construct
                // a copy-on-write owned smart pointer--a "Cow"--as output.
                //
                // We dereference that pointer to get a reference to the boxed &str, then call
                // to_owned on the &str to get an owned String, which finally we return.
                //
                // This is kind of a lot. I guess this gets easier with time?
                (*String::from_utf8_lossy(&inner[..])).to_owned()
            },
            Err(e) => panic!(e),
        };
        let header: serde_json::Value = match serde_json::from_str(&header) {
            Ok(inner) => inner,
            Err(e) => panic!(e),
        };
        let claims_set = match base64::decode(&components[1]) {
            Ok(inner) => (*String::from_utf8_lossy(&inner[..])).to_owned(),
            Err(e) => panic!(e),
        };
        let mut jwt = JWT::from_str(&claims_set).unwrap();

        // Q: why can't we take header["alg"] here?
        //
        // A: declaring alg = header["alg"] makes alg the new owner of the JsonValue. This consumes
        // the value, causing any earlier references to this structure to go out of scope. This is
        // not OK because we are somehow still using the deallocated references in the code that
        // follows? IDK. Rust is hard.
        //
        // Anyway, making it a reference makes it an immutable borrow, which avoids the ownership
        // problems.
        let alg = &header["alg"];
        if alg.is_null() {
            panic!("'alg' value in header cannot be null.");
        }
        let alg = alg.as_str().unwrap();
        match alg {
            "none" => jwt.header.alg = Alg::None,
            _ => panic!("Bad alg value.")
        }
        Result::<JWT>::Ok(jwt)
    }

    pub fn from_str(claims_set: &str) -> Result<JWT> {
        serde_json::from_str(claims_set)
            .map(|claims_set| { 
                JWT {
                    header: JWTHeader{typ:Typ::None, alg:Alg::None, cty:Cty::None},
                    claims_set
                }
            })
            .map_err(|e| { JWTError::ParseError(e) })
    }

    pub fn new() -> JWT {
        JWT {
            header: JWTHeader{typ:Typ::None, alg:Alg::None, cty:Cty::None},
            claims_set: serde_json::json!("{}")
        }
    }
}
