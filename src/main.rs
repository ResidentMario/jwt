use jwt::JWT;
use jwt::claims::ClaimSet;
use serde_json::{Value, Map};

fn main() {
    let jwt: JWT = JWT::new();
    println!("{}", jwt);

    let cs = ClaimSet::from_str("{\"foo\": \"bar\", \"baz\": \"ban\"}").unwrap();
    println!("{}", cs);
    let r: serde_json::Value = serde_json::from_str("{\"a\": \"b\"}").unwrap();
    // println!("{:?}", jwt);
    // println!("{}", jwt.encode());
    // println!("{:?}", JWT::decode_str("eyJhbGciOiAibm9uZSJ9\n.\neyJmb28iOiJiYXIifQ==\n.\n".to_owned()));
}
