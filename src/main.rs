mod lib;

use lib::*;
use std::env;
fn main() {
    let args: Vec<String> = env::args().collect();
    let qs = parse_queries(&args[1]);
    let val = validate(qs);
    let out = match val.method {
        Method::Hotp => hotp(&val.secret, val.counter.unwrap(), val.digits, val.algorithm),
        Method::Totp => totp(&val.secret, val.period.unwrap(), val.digits, val.algorithm)
    };
    println!("{}", out);
}
