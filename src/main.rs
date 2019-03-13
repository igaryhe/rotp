use base32::{Alphabet, decode};
use sha1::Sha1;
use sha2::*;
use hmac::{Hmac, Mac};
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use std::io::Cursor;
use time::get_time;
use std::string::String;

enum Digits {
    Steam,
    Digit(u32)
}

fn base32_decode(secret: &str) -> Vec<u8> {
    decode(Alphabet::RFC4648 {padding: true}, &secret.to_ascii_lowercase())
        .unwrap()
}

fn digest(bytes: Vec<u8>, counter: u64) -> Vec<u8> {
    let mut ctr = vec![];
    ctr.write_u64::<BigEndian>(counter).unwrap();
    let mut mac = Hmac::<Sha1>::new_varkey(&bytes).unwrap();
    mac.input(&ctr);
    mac.result().code().to_vec()
}

fn truncate(code: Vec<u8>) -> usize {
    (code.last().unwrap() & 0xf) as usize
}

fn extract31(code: Vec<u8>, offset: usize) -> u32 {
    let sbit_hex = &code[offset..offset + 4];
    let mut cur = Cursor::new(sbit_hex);
    cur.read_u32::<BigEndian>().unwrap() << 1 >> 1
}

fn steam_gen(decimal: u32) -> String {
    let mut dec = decimal.clone();
    let steam = vec!['2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C',
                     'D', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q',
                     'R', 'T', 'V', 'W', 'X', 'Y'];
    let mut code = String::from("");
    for _ in 0..5 {
        code.push(steam[dec as usize % 26]);
        dec = dec / 26 as u32;
    }
    code
}

fn hotp_helper(secret: &str, counter: u64) -> u32 {
    let bytes = base32_decode(secret);
    let code = digest(bytes, counter);
    let offset = truncate(code.clone());
    extract31(code, offset) % 0x7fffffff
}

fn hotp(secret: &str, counter: u64, digits: Digits) -> String {
    match digits {
        Digits::Steam => steam_gen(hotp_helper(secret, counter)),
        Digits::Digit(n) => (hotp_helper(secret, counter) % 10u32.pow(n))
            .to_string(),
    }
}

fn time_to_counter(time_step: u64) -> u64 {
    let time = get_time().sec;
    (time as u64) / time_step
}

fn totp(secret: &str, time_step: u64, digits: Digits) -> String {
    hotp(secret, time_to_counter(time_step), digits)
}

fn main() {
}
