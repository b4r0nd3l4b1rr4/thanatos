use std::fs;
use std::path::Path;

// FNV-1a seeded byte rotation — mimics legitimate locale resource encoding
fn encrypt(s: &str) -> String {
    let mut seed: u32 = 0x811C_9DC5;
    let bytes: Vec<String> = s.bytes()
        .map(|b| {
            let rot = (seed & 0x07) as u8;
            let enc = b.wrapping_add(rot).wrapping_add(37);
            seed = seed.wrapping_mul(0x0100_0193) ^ (enc as u32);
            format!("0x{:02X}", enc)
        })
        .collect();
    format!("&[{}]", bytes.join(","))
}

fn main() {
    // Show a few examples of encrypted strings
    let examples = vec![
        ("S_SHELLCODE_START", "Execution started"),
        ("S_TOKEN_STOLEN", "Handle acquired from pid"),
        ("S_AMSI_PATCHED", "Interface neutralized"),
        ("S_API_VIRTUAL_ALLOC", "Memory allocation failed"),
    ];

    println!("Example encrypted constants:\n");
    for (name, value) in &examples {
        println!("pub const {}: &[u8] = {};", name, encrypt(value));
    }
}
