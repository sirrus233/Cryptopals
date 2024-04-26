#[test]
fn challenge_1_1_hex_to_base64() {
    let bytes = cryptopals::read_hex_file("data/challenge_1_1.txt");
    let result = cryptopals::bytes_to_base64(&bytes);
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(result, expected);
}

#[test]
fn challenge_1_2_fixed_xor() {
    let bytes1 = cryptopals::read_hex_file("data/challenge_1_2a.txt");
    let bytes2 = cryptopals::read_hex_file("data/challenge_1_2b.txt");
    let result = cryptopals::fixed_xor(&bytes1, &bytes2);
    let expected = hex::decode("746865206b696420646f6e277420706c6179").unwrap();
    assert_eq!(result, expected)
}

#[test]
fn challenge_1_3_single_byte_xor_decrypt() {
    let ciphertext = cryptopals::read_hex_file("data/challenge_1_3.txt");
    let result = cryptopals::break_single_byte_xor(&ciphertext);
    let expected = "Cooking MC's like a pound of bacon".as_bytes().to_vec();
    assert_eq!(result, expected)
}

#[test]
fn challenge_1_4_detect_single_byte_xor() {
    let ciphertexts = cryptopals::read_hex_lines_file("data/challenge_1_4.txt");
    let ciphertexts = ciphertexts.iter().map(|v| v.as_slice()).collect::<Vec<_>>();
    let result = cryptopals::detect_single_byte_xor(&ciphertexts);
    let expected = "Now that the party is jumping\n".as_bytes().to_vec();
    assert_eq!(result, expected)
}
