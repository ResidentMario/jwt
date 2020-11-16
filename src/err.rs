use std::{error::Error, fmt, result};

#[derive(Debug)]
pub enum JWTError {
    ParseError(String),
    SchemaError,
    NotImplementedError
}

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