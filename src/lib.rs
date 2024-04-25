use base64::{engine::general_purpose::STANDARD as base64, Engine};
use counter::Counter;
use std::{collections::HashMap, fs};

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

pub fn bytes_to_base64(bytes: &Vec<u8>) -> String {
    base64.encode(bytes)
}

pub fn fixed_xor(bytes1: &Vec<u8>, bytes2: &Vec<u8>) -> Vec<u8> {
    if bytes1.len() != bytes2.len() {
        panic!("Can't do fixed-size XOR on vectors of different lengths.");
    }

    bytes1
        .iter()
        .zip(bytes2.iter())
        .map(|(&byte1, &byte2)| byte1 ^ byte2)
        .collect()
}

fn score_english_plaintext(text: &Vec<u8>) -> f64 {
    let expected_frequencies = HashMap::from([
        ('E', 12.02),
        ('T', 9.10),
        ('A', 8.12),
        ('O', 7.68),
        ('I', 7.31),
        ('N', 6.95),
        ('S', 6.28),
        ('R', 6.02),
        ('H', 5.92),
        ('D', 4.32),
        ('L', 3.98),
        ('U', 2.88),
        ('C', 2.71),
        ('M', 2.61),
        ('F', 2.30),
        ('Y', 2.11),
        ('W', 2.09),
        ('G', 2.03),
        ('P', 1.82),
        ('B', 1.49),
        ('V', 1.11),
        ('K', 0.69),
        ('X', 0.17),
        ('Q', 0.11),
        ('J', 0.10),
        ('Z', 0.07),
    ]);

    if text.iter().any(|c| !c.is_ascii()) {
        return f64::MAX;
    }

    let text_length = text.len() as f64;

    if text
        .iter()
        .filter(|&c| !c.is_ascii_alphabetic() && c != &32u8)
        .collect::<Vec<_>>()
        .len() as f64
        > text_length * 0.2
    {
        return f64::MAX;
    }

    let counts = text
        .iter()
        .flat_map(|byte| match byte {
            byte if byte.is_ascii_lowercase() => Some((byte - 32) as char),
            byte if byte.is_ascii_uppercase() => Some(*byte as char),
            _ => None,
        })
        .collect::<Counter<_>>();

    ('A'..'Z')
        .map(|c| {
            let actual_count = match counts.get(&c) {
                Some(count) => *count as f64,
                None => 0f64,
            };
            let actual_frequency = (actual_count / text_length) * 100f64;
            let expected_frequency = expected_frequencies
                .get(&c)
                .expect(&format!("Missing char in frequency table: {c}"));
            (actual_frequency - expected_frequency) / expected_frequency
        })
        .sum()
}

fn repeating_key(ciphertext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    key.iter().cycle().take(ciphertext.len()).cloned().collect()
}

pub fn decrypt_single_byte_xor(ciphertext: &Vec<u8>) -> Vec<u8> {
    match (0..u8::MAX)
        .map(|i| {
            let try_key = repeating_key(&ciphertext, &vec![i]);
            let plaintext = fixed_xor(&ciphertext, &try_key);
            (score_english_plaintext(&plaintext), i)
        })
        .min_by(|(a, _), (b, _)| {
            a.partial_cmp(b)
                .expect(&format!("Cannot compare {a} and {b}"))
        })
        .unwrap()
    {
        (_, key_byte) => fixed_xor(&ciphertext, &repeating_key(&ciphertext, &vec![key_byte])),
    }
}
