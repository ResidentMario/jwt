// use jwt::JWT;
use jwt::claims::ClaimSet;

fn main() {
    let cs = ClaimSet::from_str("{\"foo\": \"bar\", \"baz\": \"ban\"}").unwrap();
    println!("{}", cs.as_str())
    // let r: serde_json::Value = serde_json::from_str("{\"a\": \"b\"}").unwrap();
    // let r: serde_json::Map<String, serde_json::Value> = serde_json::from_str("{\"a\": \"b\"}").unwrap();
    // let r = serde_json::from_str("{\"a\": \"b\"}").unwrap();
    // println!("{:?}", r);
    // let jwt: JWT = JWT::new();
    // println!("{}", jwt);
    // let jwt: Result<JWT> = JWT::from_str("{\"\"foo\": \"bar\"}");
    // match jwt {
    //     Ok(jwt) => println!("{:?}", jwt),
    //     Err(e) => println!("{}", e),
    // }
    // println!("{:?}", jwt);
    // println!("{}", jwt.encode());
    // println!("{:?}", JWT::decode_str("eyJhbGciOiAibm9uZSJ9\n.\neyJmb28iOiJiYXIifQ==\n.\n".to_owned()));
}
