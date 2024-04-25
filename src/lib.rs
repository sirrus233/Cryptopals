use base64::{engine::general_purpose::STANDARD as base64, Engine};
use hex;
use std::fs;

pub fn read_hex_file(path: &str) -> Vec<u8> {
    let contents = match fs::read_to_string(path) {
        Err(e) => panic!("Couldn't read {}: {}", path, e),
        Ok(contents) => contents,
    };

    match hex::decode(&contents) {
        Err(e) => panic!("Couldn't decode byte-string: {}", e),
        Ok(bytes) => bytes,
    }
}

pub fn bytes_to_base64(bytes: Vec<u8>) -> String {
    base64.encode(bytes)
}
