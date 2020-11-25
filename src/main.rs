use jwt::{JWT,JsonSerializable};
use jwt::claims::ClaimSet;
use serde_json::{Value, Map};

fn main() {
    println!("{:?}", JWT::decode_b64("eyJhbGciOiAibm9uZSJ9\n.\neyJmb28iOiJiYXIifQ==\n.\n"));
}
