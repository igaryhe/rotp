use base32::{Alphabet, decode};
use sha1::Sha1;
use sha2::*;
use hmac::{Hmac, Mac};
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use std::io::Cursor;
use time::get_time;
use std::string::String;
use clap::{App, load_yaml};
use std::str::FromStr;
use generic_array;
use digest::{Input, BlockInput, FixedOutput, Reset};
use std::fmt::Debug;

enum Digits {
    Steam,
    Digit(u32)
}

enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

impl From<&str> for Algo {
    fn from(s: &str) -> Self {
        match s {
            "sha1" => Algo::Sha1,
            "sha256" => Algo::Sha256,
            "sha512" => Algo::Sha512,
            _ => unreachable!("Unexpected algorithm"),
        }
    }
}

impl Algo {
    fn create_digest(&self, key: &[u8]) -> Box<dyn InnerDigest> {
        match self {
            Algo::Sha1 => Box::new(Hmac::<Sha1>::create(key)),
            Algo::Sha256 => Box::new(Hmac::<Sha256>::create(key)),
            Algo::Sha512 => Box::new(Hmac::<Sha512>::create(key)),
        }
    }
}

trait InnerDigest {
    fn create(key: &[u8]) -> Self where Self: Sized;
    fn update(&mut self, data: &[u8]);
    fn digest(self: Box<Self>) -> Vec<u8>;
}

impl<D: Clone> InnerDigest for Hmac<D>
    where D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
          D::BlockSize: generic_array::ArrayLength<u8> + Debug,
          Hmac<D>: hmac::Mac,
{
    fn create(key: &[u8]) -> Self {
        Self::new_varkey(key).unwrap()
    }

    fn update(&mut self, data: &[u8]) {
        self.input(&data);
    }

    fn digest(self: Box<Self>) -> Vec<u8> {
        self.result().code().to_vec()
    }
}

fn base32_decode(secret: &str) -> Vec<u8> {
    decode(Alphabet::RFC4648 {padding: true}, &secret.to_ascii_lowercase())
        .unwrap()
}

fn digest(bytes: Vec<u8>, counter: u64, algo: Algo) -> Vec<u8> {
    let mut ctr = vec![];
    ctr.write_u64::<BigEndian>(counter).unwrap();

    let mut d = algo.create_digest(&bytes);
    d.update(&ctr);
    d.digest()
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

fn hotp_helper(secret: &str, counter: u64, algo: Algo) -> u32 {
    let bytes = base32_decode(secret);
    let code = digest(bytes, counter, algo);
    let offset = truncate(code.clone());
    extract31(code, offset) % 0x7fffffff
}

fn hotp(secret: &str, counter: u64, digits: Digits, algo: Algo) -> String {
    match digits {
        Digits::Steam => steam_gen(hotp_helper(secret, counter, algo)),
        Digits::Digit(n) => (hotp_helper(secret, counter, algo) % 10u32.pow(n))
            .to_string(),
    }
}

fn time_to_counter(time_step: u64) -> u64 {
    let time = get_time().sec;
    (time as u64) / time_step
}

fn totp(secret: &str, time_step: u64, digits: Digits, algo: Algo) -> String {
    hotp(secret, time_to_counter(time_step), digits, algo)
}

fn main() {
    let yaml = load_yaml!("cli.yaml");
    let matches = App::from_yaml(yaml).get_matches();
    if matches.is_present("hotp") {
        let counter = u64::from_str(matches.value_of("counter").unwrap()).unwrap();
        let secret = matches.value_of("secret").unwrap();
        let digits = u32::from_str(matches.value_of("digits").unwrap()).unwrap();
        let out = hotp(secret, counter, Digits::Digit(digits), Algo::Sha1);
        println!("{}", out);
    }
    if matches.is_present("totp") {
        let secret = matches.value_of("secret").unwrap();
        let digits = matches.value_of("digits").unwrap();
        let period = u64::from_str(matches.value_of("period").unwrap()).unwrap();
        let algo = matches.value_of("algorithm").unwrap().into();
        let num = u32::from_str(digits);
        if (digits == "s") {
            let out = totp(secret, period, Digits::Steam, algo);
            println!("{}", out);
        } else {
            let out = match num {
                Ok(n) => totp(secret, period, Digits::Digit(n), algo),
                Err(_) => panic!("Invalid digits!")
            };
            println!("{}", out);
        }
    }
}
