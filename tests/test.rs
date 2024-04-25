use cryptopals;

#[test]
fn challenge_1_1_hex_to_base64() {
    let bytes = cryptopals::read_hex_file("data/challenge_1_1.txt");
    let result = cryptopals::bytes_to_base64(bytes);
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(result, expected);
}
