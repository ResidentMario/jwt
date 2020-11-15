use jwt::{JWT, Result};
// use json::parse;

fn main() {
    let jwt: JWT = JWT::from_str("{\"foo\": \"bar\"}").unwrap();
    // let jwt: Result<JWT> = JWT::from_str("{\"\"foo\": \"bar\"}");
    // match jwt {
    //     Ok(jwt) => println!("{:?}", jwt),
    //     Err(e) => println!("{}", e),
    // }
    // println!("{:?}", jwt);
    // println!("{}", jwt.encode());
    println!("{:?}", JWT::decode_str("eyJhbGciOiAibm9uZSJ9\n.\neyJmb28iOiJiYXIifQ==\n.\n".to_owned()));
}
