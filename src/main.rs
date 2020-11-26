use jwt::{JWT,JsonSerializable};

fn main() {
    // println!("{:?}", JWT::decode_b64("eyJhbGciOiAibm9uZSJ9\n.\neyJmb28iOiJiYXIifQ==\n.\n"));
    let mut jwt = JWT::decode_str(
        "{\"alg\": \"none\"}\n.\n{\"foo\":\"bar\"}\n.\nHELLO"
    ).unwrap();
    jwt.header.alg = jwt::header::Alg::HS256;
    println!("{}", jwt.encode_str());
}
