use sha1::Sha1;
use sha2::*;
use hmac::{Hmac, Mac};
use byteorder::BigEndian;
use std::string::String;
use generic_array;
use digest::{Input, BlockInput, FixedOutput, Reset};
use std::fmt::Debug;
use std::collections::HashMap;

pub enum Digits {
    Steam,
    Digit(u32)
}

pub enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

pub struct Otp {
    pub secret: String,
    pub digits: Digits,
    pub algorithm: Algo,
    pub period: Option<u64>,
    pub counter: u64
}

impl From<&str> for Algo {
    fn from(s: &str) -> Self {
        match s {
            "sha1" => Algo::Sha1,
            "sha256" => Algo::Sha256,
            "sha512" => Algo::Sha512,
            _ => panic!("Unexpected algorithm"),
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
    use base32::{Alphabet, decode};
    decode(Alphabet::RFC4648 {padding: true}, &secret.to_ascii_lowercase())
        .expect("Unable to decode base32 secret")
}

fn digest(bytes: Vec<u8>, counter: u64, algo: Algo) -> Vec<u8> {
    use byteorder::WriteBytesExt;
    
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
    use byteorder::ReadBytesExt;
    use std::io::Cursor;
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

pub fn otp(otp: Otp) -> String {
    match otp.digits {
        Digits::Steam =>
            steam_gen(hotp_helper(&otp.secret, otp.counter, otp.algorithm)),
        Digits::Digit(n) =>
            (hotp_helper(&otp.secret, otp.counter, otp.algorithm) % 10u32.pow(n))
            .to_string(),
    }
}

fn time_to_counter(time_step: u64) -> u64 {
    use time::get_time;
    
    let time = get_time().sec;
    (time as u64) / time_step
}

pub fn parse_queries(uri: &str) -> HashMap<String, String> {
    use url::Url;
    use std::borrow::Cow;
    
    let url = Url::parse(uri).expect("Wrong URI format");
    let mut pairs = url.query_pairs();
    let mut query = HashMap::new();
    let scheme = url.host_str().expect("Wrong URI format").to_string();
    query.insert("method".to_string(), scheme);
    let count = pairs.count();
    for _ in 0..count {
        let q = pairs.next();
        match q {
            Some((Cow::Borrowed(name), Cow::Borrowed(value)))
                => query.insert(name.to_string(), value.to_string()),
            _ => panic!("Wrong method")
        };
    }
    if query["method"] == "totp" {
        query.entry("algorithm".to_string()).or_insert("sha1".to_string());
        query.entry("digits".to_string()).or_insert("6".to_string());
        query.entry("period".to_string()).or_insert("30".to_string());
    }
    query
}

pub fn validate(query: HashMap<String, String>) -> Otp {
    let digits = match query["digits"].as_str() {
        "s" => Digits::Steam,
        n => Digits::Digit(n.parse()
                           .expect("Digits need to be an integer range from 1 to 9 or a character s"))
    };
    let secret = query["secret"].clone();
    if query["method"] == "totp" {
       Otp {
           secret,
           digits,
           period: Some(query["period"].parse()
                        .expect("Invalid period format, need to be an integer")),
           algorithm: query["algorithm"].as_str().into(),
           counter: time_to_counter(query["period"].parse().unwrap())
       }
    } else if query["method"] == "hotp" {
        Otp {
            secret,
            digits,
            period: None,
            algorithm: Algo::Sha1,
            counter: query["counter"].parse()
                .expect("Invalid period format, need to be an integer")
        }
    }
    else {panic!("Wrong method");}
}
