use jwt::{JWT, Result};
// use json::parse;

fn main() {
    // let jwt: JWT = JWT::from_str("{\"foo\": \"bar\"}").unwrap();
    let jwt: Result<JWT> = JWT::from_str("{\"\"foo\": \"bar\"}");
    println!("{:?}", jwt);
    // println!("{}", jwt.encode());
    // println!("{:?}", JWT::decode("eyJhbGciOiAibm9uZSJ9\n.\neyJmb28iOiJiYXIifQ==\n.\n".to_owned()));
}
