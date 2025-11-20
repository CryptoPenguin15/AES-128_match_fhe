use crate::aes128_tables::SBOX;

pub const KEYSIZE: usize = 16;
pub const BLOCKSIZE: usize = 16;
pub const ROUNDS: usize = 10;
pub const ROUNDKEYSIZE: usize = BLOCKSIZE * (ROUNDS + 1);

const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

pub fn key_expansion(key: &[u8; 16]) -> [u8; 16 * 11] {
    let mut xk = [0u8; ROUNDKEYSIZE];
    xk[0..KEYSIZE].copy_from_slice(key);

    let mut i = KEYSIZE;
    let mut tmp = [0u8; 4];

    while i < ROUNDKEYSIZE {
        tmp.copy_from_slice(&xk[i - 4..i]);

        if i % KEYSIZE == 0 {
            tmp.rotate_left(1);
            for j in 0..4 {
                tmp[j] = SBOX[tmp[j] as usize];
            }
            tmp[0] ^= RCON[i / KEYSIZE];
        }

        for j in 0..4 {
            xk[i] = xk[i - KEYSIZE] ^ tmp[j];
            i += 1;
        }
    }

    return xk;
}
