use jwt::{JWT,JsonSerializable};

fn main() {
    println!("{:?}", JWT::decode_b64("eyJhbGciOiAibm9uZSJ9\n.\neyJmb28iOiJiYXIifQ==\n.\n"));
}
