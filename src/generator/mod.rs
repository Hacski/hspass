use rand::seq::SliceRandom;
use rand::thread_rng;

pub struct PasswordGeneratorOptions {
    pub length: usize,
    pub use_uppercase: bool,
    pub use_lowercase: bool,
    pub use_numbers: bool,
    pub use_symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordGeneratorOptions {
    fn default() -> Self {
        Self {
            length: 24,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_symbols: true,
            avoid_ambiguous: false,
        }
    }
}

pub fn generate_password(opts: &PasswordGeneratorOptions) -> String {
    let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let lowercase = "abcdefghijklmnopqrstuvwxyz";
    let numbers = "0123456789";
    let symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    let ambig = "O0l1I|i";

    let mut char_pool = String::new();
    let mut guaranteed = Vec::new();
    let mut rng = thread_rng();

    if opts.use_uppercase {
        let pool: String = if opts.avoid_ambiguous {
            uppercase.chars().filter(|c| !ambig.contains(*c)).collect()
        } else {
            uppercase.to_string()
        };
        if !pool.is_empty() {
            char_pool.push_str(&pool);
            guaranteed.push(pool.as_bytes().choose(&mut rng).copied().unwrap());
        }
    }

    if opts.use_lowercase {
        let pool: String = if opts.avoid_ambiguous {
            lowercase.chars().filter(|c| !ambig.contains(*c)).collect()
        } else {
            lowercase.to_string()
        };
        if !pool.is_empty() {
            char_pool.push_str(&pool);
            guaranteed.push(pool.as_bytes().choose(&mut rng).copied().unwrap());
        }
    }

    if opts.use_numbers {
        let pool: String = if opts.avoid_ambiguous {
            numbers.chars().filter(|c| !ambig.contains(*c)).collect()
        } else {
            numbers.to_string()
        };
        if !pool.is_empty() {
            char_pool.push_str(&pool);
            guaranteed.push(pool.as_bytes().choose(&mut rng).copied().unwrap());
        }
    }

    if opts.use_symbols {
        let pool: String = if opts.avoid_ambiguous {
            symbols.chars().filter(|c| !ambig.contains(*c)).collect()
        } else {
            symbols.to_string()
        };
        if !pool.is_empty() {
            char_pool.push_str(&pool);
            guaranteed.push(pool.as_bytes().choose(&mut rng).copied().unwrap());
        }
    }

    if char_pool.is_empty() {
        char_pool.push_str(lowercase);
    }

    let pool_bytes = char_pool.as_bytes();
    let mut password = guaranteed;

    while password.len() < opts.length {
        let byte = pool_bytes.choose(&mut rng).copied().unwrap();
        password.push(byte);
    }

    password.shuffle(&mut rng);
    String::from_utf8(password).unwrap_or_else(|_| "GeneratedPassword123!".to_string())
}

const PASSPHRASE_WORDLIST: &[&str] = &[
    "quantum", "cipher", "nebula", "shield", "phoenix", "horizon", "vortex", "starlight",
    "titanium", "solstice", "avalanche", "catalyst", "obsidian", "zenith", "hyperion",
    "glacier", "supernova", "aurora", "paradox", "velocity", "prism", "sanctuary", "eclipse",
];

pub fn generate_passphrase(word_count: usize, separator: &str) -> String {
    let mut rng = thread_rng();
    let words: Vec<&str> = (0..word_count)
        .map(|_| *PASSPHRASE_WORDLIST.choose(&mut rng).unwrap_or(&"hspass"))
        .collect();
    words.join(separator)
}
