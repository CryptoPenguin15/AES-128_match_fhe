use crate::aes128_keyschedule::BLOCKSIZE;
use crate::aes128_keyschedule::KEYSIZE;
use crate::aes128_keyschedule::ROUNDKEYSIZE;
use crate::aes128_keyschedule::ROUNDS;

use crate::aes128_tables::GMUL2;
use crate::aes128_tables::GMUL3;
use crate::aes128_tables::SBOX;

//use rayon::prelude::*;

#[cfg(feature = "gpu")]
use tfhe::CompressedServerKey;
#[cfg(not(feature = "gpu"))]
use tfhe::generate_keys;
use tfhe::prelude::*;
use tfhe::{ClientKey, ConfigBuilder, FheUint8, MatchValues, set_server_key};

use std::time::Instant;

fn print_hex_fhe_u8(label: &str, idx: usize, enc_data: &Vec<FheUint8>, ck: &ClientKey) {
    let mut state: Vec<u32> = Vec::new();

    for (_, enc_value) in enc_data.iter().enumerate() {
        state.push(enc_value.decrypt(ck));
    }

    let hex_output: String = state.iter().map(|byte| format!("{:02x}", byte)).collect();

    println!("{}  {:?} {}", label, idx, hex_output);
}

#[inline]
fn add_round_key_fhe(state: &mut [FheUint8], rkey: &[FheUint8]) {
    for i in 0..16 {
        state[i] = &state[i] ^ &rkey[i];
    }
}

#[inline]
fn sub_bytes_fhe(state: &mut [FheUint8], sbox_mv: &MatchValues<u8>) {
    let start = Instant::now();

    for byte in state.iter_mut() {
        let (byte1, _res1_): (FheUint8, _) = byte.match_value(sbox_mv).unwrap();
        *byte = byte1;
    }

    println!("sub_bytes_fhe       {:.2?}", start.elapsed());
}

#[inline]
fn shift_rows_fhe(state: &mut [FheUint8]) {
    let tmp = state.to_vec();

    // column 0
    state[0] = tmp[0].clone();
    state[1] = tmp[5].clone();
    state[2] = tmp[10].clone();
    state[3] = tmp[15].clone();

    // column 1
    state[4] = tmp[4].clone();
    state[5] = tmp[9].clone();
    state[6] = tmp[14].clone();
    state[7] = tmp[3].clone();

    // column 2
    state[8] = tmp[8].clone();
    state[9] = tmp[13].clone();
    state[10] = tmp[2].clone();
    state[11] = tmp[7].clone();

    // column 3
    state[12] = tmp[12].clone();
    state[13] = tmp[1].clone();
    state[14] = tmp[6].clone();
    state[15] = tmp[11].clone();
}

#[inline]
fn mix_columns_fhe(state: &mut [FheUint8], gmul2_mv: &MatchValues<u8>, gmul3_mv: &MatchValues<u8>) {
    let start = Instant::now();
    let mut tmp = state.to_vec().clone();

    for c in 0..4 {
        let col_start = c * 4;

        let (byte2, _): (FheUint8, _) = state[col_start].match_value(gmul2_mv).unwrap();
        let (byte3, _): (FheUint8, _) = state[col_start + 1].match_value(gmul3_mv).unwrap();
        tmp[col_start] = byte2 ^ byte3 ^ &state[col_start + 2] ^ &state[col_start + 3];

        let (byte2, _): (FheUint8, _) = state[col_start + 1].match_value(gmul2_mv).unwrap();
        let (byte3, _): (FheUint8, _) = state[col_start + 2].match_value(gmul3_mv).unwrap();
        tmp[col_start + 1] = &state[col_start] ^ byte2 ^ byte3 ^ &state[col_start + 3];

        let (byte2, _): (FheUint8, _) = state[col_start + 2].match_value(gmul2_mv).unwrap();
        let (byte3, _): (FheUint8, _) = state[col_start + 3].match_value(gmul3_mv).unwrap();
        tmp[col_start + 2] = &state[col_start] ^ &state[col_start + 1] ^ byte2 ^ byte3;

        let (byte2, _): (FheUint8, _) = state[col_start + 3].match_value(gmul2_mv).unwrap();
        let (byte3, _): (FheUint8, _) = state[col_start].match_value(gmul3_mv).unwrap();
        tmp[col_start + 3] = byte3 ^ &state[col_start + 1] ^ &state[col_start + 2] ^ byte2;
    }

    state.clone_from_slice(&tmp);
    println!("m_col time       {:.2?}", start.elapsed());
}

fn enc_vec(input: &[u8], ck: &ClientKey) -> Vec<FheUint8> {
    let mut enc_vec: Vec<FheUint8> = Vec::new();
    for &value in input.iter() {
        match FheUint8::try_encrypt(value, ck) {
            Ok(encrypted) => enc_vec.push(encrypted),
            Err(e) => {
                println!("Failed to encrypt the value: {:?}", e);
            }
        }
    }
    enc_vec
}

fn gen_match_values() -> (MatchValues<u8>, MatchValues<u8>, MatchValues<u8>) {
    let sbox_mv = MatchValues::new(
        SBOX.iter()
            .enumerate()
            .map(|(i, &v)| (i as u8, v))
            .collect(),
    )
    .unwrap();

    let gmul2_mv = MatchValues::new(
        GMUL2
            .iter()
            .enumerate()
            .map(|(i, &v)| (i as u8, v))
            .collect(),
    )
    .unwrap();

    let gmul3_mv = MatchValues::new(
        GMUL3
            .iter()
            .enumerate()
            .map(|(i, &v)| (i as u8, v))
            .collect(),
    )
    .unwrap();

    (sbox_mv, gmul2_mv, gmul3_mv)
}

fn gen_keys() -> ClientKey {
    // offline-phase
    let start = Instant::now();
    let config = ConfigBuilder::default().build();
    #[cfg(not(feature = "gpu"))]
    let (client_key, server_keys) = generate_keys(config);
    #[cfg(feature = "gpu")]
    let client_key = ClientKey::generate(config);
    #[cfg(feature = "gpu")]
    let compressed_server_key = CompressedServerKey::new(&client_key);
    #[cfg(feature = "gpu")]
    let gpu_key = compressed_server_key.decompress_to_gpu();
    println!("gen keys time       {:.2?}", start.elapsed());

    // cloud setup
    #[cfg(not(feature = "gpu"))]
    set_server_key(server_keys);
    #[cfg(feature = "gpu")]
    set_server_key(gpu_key);

    client_key
}

pub fn encrypt_block_fhe(
    input: &[u8; KEYSIZE],
    xk: &[u8; ROUNDKEYSIZE],
    output: &mut [u8; BLOCKSIZE],
) {
    let mut state = [0u8; BLOCKSIZE];
    state.copy_from_slice(input);

    let ck = gen_keys();
    let mut state_ck = enc_vec(&state, &ck);
    let xk_ck = enc_vec(xk, &ck);
    let (sbox_mv, gmul2_mv, gmul3_mv) = gen_match_values();

    print_hex_fhe_u8("input", 0, &state_ck, &ck);

    add_round_key_fhe(&mut state_ck, &xk_ck[..BLOCKSIZE]);
    print_hex_fhe_u8("k_sch", 0, &state_ck, &ck);

    for round in 1..ROUNDS {
        sub_bytes_fhe(&mut state_ck, &sbox_mv);
        print_hex_fhe_u8("s_box", round, &state_ck, &ck);

        shift_rows_fhe(&mut state_ck);
        print_hex_fhe_u8("s_row", round, &state_ck, &ck);

        mix_columns_fhe(&mut state_ck, &gmul2_mv, &gmul3_mv);
        print_hex_fhe_u8("m_col", round, &state_ck, &ck);

        add_round_key_fhe(&mut state_ck, &xk_ck[round * KEYSIZE..ROUNDKEYSIZE]);
        print_hex_fhe_u8("k_sch", round, &state_ck, &ck);
    }

    sub_bytes_fhe(&mut state_ck, &sbox_mv);
    print_hex_fhe_u8("s_box", 10, &state_ck, &ck);

    shift_rows_fhe(&mut state_ck);
    print_hex_fhe_u8("s_row", 10, &state_ck, &ck);

    add_round_key_fhe(&mut state_ck, &xk_ck[KEYSIZE * ROUNDS..ROUNDKEYSIZE]);
    print_hex_fhe_u8("k_sch", 10, &state_ck, &ck);

    let mut state: Vec<u8> = Vec::new();
    for (_, enc_value) in state_ck.iter().enumerate() {
        state.push(enc_value.decrypt(&ck));
    }

    output.copy_from_slice(&state);
}
