mod lib;

use lib::*;
use std::env;
fn main() {
    let args: Vec<String> = env::args().collect();
    let qs = parse_queries(&args[1]);
    let val = validate(qs);
    println!("{}", otp(val));
}
