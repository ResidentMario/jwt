use jwt::JWT;
// use json::parse;

fn main() {
    let jwt: JWT = JWT::new("{\"foo\": \"bar\"}");
    println!("{:?}", jwt);
    println!("{}", jwt.encode());
    println!("{:?}", JWT::decode("eyJhbGciOiAibm9uZSJ9\n.\neyJmb28iOiJiYXIifQ==\n.\n".to_owned()));
}
