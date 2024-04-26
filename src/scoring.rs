use counter::Counter;

fn char_frequency(c: char) -> f64 {
    match c {
        'E' => 0.1202,
        'T' => 0.0910,
        'A' => 0.0812,
        'O' => 0.0768,
        'I' => 0.0731,
        'N' => 0.0695,
        'S' => 0.0628,
        'R' => 0.0602,
        'H' => 0.0592,
        'D' => 0.0432,
        'L' => 0.0398,
        'U' => 0.0288,
        'C' => 0.0271,
        'M' => 0.0261,
        'F' => 0.0230,
        'Y' => 0.0211,
        'W' => 0.0209,
        'G' => 0.0203,
        'P' => 0.0182,
        'B' => 0.0149,
        'V' => 0.0111,
        'K' => 0.0069,
        'X' => 0.0017,
        'Q' => 0.0011,
        'J' => 0.0010,
        'Z' => 0.0007,
        _ => panic!("Can't get frequency of non-alpha char: {}", c),
    }
}

fn is_nonsense(text: &[u8]) -> bool {
    const NONSENSE_THRESHOLD: f64 = 0.1;
    const SPACE_CHAR: u8 = 32;

    let allowed_nonsense_chars = text.len() as f64 * NONSENSE_THRESHOLD;
    let num_nonsense_chars = text
        .iter()
        .filter(|&&c| !c.is_ascii_alphabetic() && c != SPACE_CHAR)
        .collect::<Vec<_>>()
        .len() as f64;

    num_nonsense_chars > allowed_nonsense_chars
}

pub fn score_english_plaintext(text: &[u8]) -> f64 {
    if is_nonsense(text) {
        return f64::MAX;
    }

    let alpha_counts = text
        .iter()
        .flat_map(|byte| match byte {
            byte if byte.is_ascii_lowercase() => Some((byte - 32) as char),
            byte if byte.is_ascii_uppercase() => Some(*byte as char),
            _ => None,
        })
        .collect::<Counter<_>>();

    let errors = ('A'..'Z').map(|c| {
        let actual_count = match alpha_counts.get(&c) {
            Some(&count) => count as f64,
            None => 0f64,
        };
        let actual_frequency = actual_count / text.len() as f64;
        let expected_frequency = char_frequency(c);
        (actual_frequency - expected_frequency) / expected_frequency
    });

    errors.sum()
}
