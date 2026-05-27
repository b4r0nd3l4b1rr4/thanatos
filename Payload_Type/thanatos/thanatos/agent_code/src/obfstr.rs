// String resource decoding — uses byte rotation with position-seeded offset
// Pattern matches legitimate locale/resource string decoders (ICU, .NET)

#[inline(always)]
pub fn d(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(data.len());
    let mut seed: u32 = 0x811C_9DC5; // FNV-1a offset basis
    for &b in data.iter() {
        let rot = (seed & 0x07) as u8;
        out.push(b.wrapping_sub(rot).wrapping_sub(37));
        seed = seed.wrapping_mul(0x0100_0193) ^ (b as u32); // FNV-1a step
    }
    unsafe { String::from_utf8_unchecked(out) }
}

include!(concat!(env!("OUT_DIR"), "/strings_enc.rs"));
