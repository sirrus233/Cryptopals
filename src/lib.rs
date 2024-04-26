use base64::{engine::general_purpose::STANDARD as base64, Engine};
use std::fs;

mod scoring;
use scoring::score_english_plaintext;

pub fn read_file(path: &str) -> String {
    match fs::read_to_string(path) {
        Err(e) => panic!("Couldn't read {}: {}", path, e),
        Ok(contents) => contents,
    }
}

fn decode_hex(hex_string: &str) -> Vec<u8> {
    match hex::decode(hex_string) {
        Err(e) => panic!("Couldn't decode hex string: {}", e),
        Ok(bytes) => bytes,
    }
}

pub fn read_hex_file(path: &str) -> Vec<u8> {
    decode_hex(&read_file(path))
}

pub fn read_hex_lines_file(path: &str) -> Vec<Vec<u8>> {
    read_file(path)
        .split('\n')
        .map(|line| decode_hex(line))
        .collect::<Vec<_>>()
}

pub fn bytes_to_base64(bytes: &[u8]) -> String {
    base64.encode(bytes)
}

pub fn fixed_xor(bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    if bytes1.len() != bytes2.len() {
        panic!("Can't do fixed-size XOR on vectors of different lengths.");
    }

    bytes1
        .iter()
        .zip(bytes2.iter())
        .map(|(byte1, byte2)| byte1 ^ byte2)
        .collect()
}

fn repeating_key(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    key.iter().cycle().take(ciphertext.len()).cloned().collect()
}

pub fn decrypt_single_byte_xor(ciphertext: &[u8], key: u8) -> Vec<u8> {
    fixed_xor(ciphertext, &repeating_key(ciphertext, &vec![key]))
}

pub fn break_single_byte_xor(ciphertext: &[u8]) -> Vec<u8> {
    let (key, _) = (0..u8::MAX)
        .map(|i| score_english_plaintext(&decrypt_single_byte_xor(ciphertext, i)))
        .enumerate()
        .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
        .unwrap();

    decrypt_single_byte_xor(ciphertext, key as u8)
}

pub fn detect_single_byte_xor(ciphertexts: &[&[u8]]) -> Vec<u8> {
    let (_, best_text) = ciphertexts
        .iter()
        .map(|ciphertext| break_single_byte_xor(ciphertext))
        .map(|plaintext| (score_english_plaintext(&plaintext), plaintext))
        .min_by(|(a, _), (b, _)| a.partial_cmp(b).unwrap())
        .unwrap();

    best_text
}

pub fn repeating_key_xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    fixed_xor(data, &repeating_key(data, key))
}
