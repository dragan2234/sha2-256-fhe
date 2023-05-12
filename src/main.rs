use std::ops::Neg;

use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint32};
use tfhe::prelude::*;


struct InputCiphertext {
    inner: Vec<FheUint32>,
}

impl InputCiphertext {
    fn encrypt(x: Vec<u32>, client_key: &tfhe::ClientKey) -> Self {
        let inner = x.iter()
            .copied() // <- iter on u32 not &u32
            .map(|value| {
                FheUint32::try_encrypt(value, client_key).unwrap()
            }).collect();
        Self { inner }
    }
}

struct OutputSha256 {
    inner: Vec<u32>,
}

impl OutputSha256 {
    fn decrypt_final(ct_vec: Vec<FheUint32>,  client_key: &tfhe::ClientKey) -> Self {
        let inner = ct_vec.clone().iter().map(|value| {
            value.decrypt(&client_key)
        }).collect();
        Self { inner }
    }

    fn print_hex(&self) {
        let hex_vec: Vec<String> = self.inner.iter().map(|value| format!("{:08x}", value)).collect();
        let hex_string = hex_vec.join("");
        println!("{}", hex_string);
    }
}

fn main() {
    use std::time::Instant;
    let now = Instant::now();
    {

    let config = ConfigBuilder::all_disabled()
        .enable_default_uint32()
        .build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);

    let input_message = "abc";

    let padded_input = padded_input(input_message);


    let h_vec: Vec<u32> = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ].to_vec();

    let k_vec: Vec<u32> = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ].to_vec();

    // Server side
    set_server_key(server_key);


    let mut h_ciphertext = InputCiphertext::encrypt(h_vec.clone(), &client_key);

    let k_ciphertext = InputCiphertext::encrypt(k_vec.clone(), &client_key);


    let mut first_32: FheUint32 = h_ciphertext.inner.get(0).unwrap().clone();
    let mut second_32: FheUint32 = h_ciphertext.inner.get(1).unwrap().clone();
    let mut third_32: FheUint32 = h_ciphertext.inner.get(2).unwrap().clone();
    let mut fourth_32: FheUint32 = h_ciphertext.inner.get(3).unwrap().clone();
    let mut fifth_32: FheUint32 = h_ciphertext.inner.get(4).unwrap().clone();
    let mut sixth_32: FheUint32 = h_ciphertext.inner.get(5).unwrap().clone();
    let mut seventh_32: FheUint32 = h_ciphertext.inner.get(6).unwrap().clone();
    let mut eight_32: FheUint32 = h_ciphertext.inner.get(7).unwrap().clone();



    for chunk in padded_input.chunks(16) {
        let chunk_padded_input: Vec<u32> = chunk.to_vec();

        let mut input_ciphertext = InputCiphertext::encrypt(chunk_padded_input, &client_key);

        for i in 16..64 {
            let w_i_minus_2 = input_ciphertext.inner.get(i-2).unwrap().clone();
            let w_i_minus_7 = input_ciphertext.inner.get(i-7).unwrap().clone();
            let w_i_minus_15 = input_ciphertext.inner.get(i-15).unwrap().clone();
            let w_i_minus_16 = input_ciphertext.inner.get(i-16).unwrap().clone();
            let sigma_one_res = sigma_one(w_i_minus_2).clone();
            let sigma_zero_res = sigma_zero(w_i_minus_15).clone();

            let w_i = sigma_one_res.clone() + w_i_minus_7 + sigma_zero_res.clone() + w_i_minus_16;
            input_ciphertext.inner.push(w_i);
        }

        let test_vec = OutputSha256::decrypt_final(input_ciphertext.inner.clone(), &client_key);

        OutputSha256::print_hex(&test_vec);

        let mut t_1: FheUint32;
        let mut t_2: FheUint32;
        let mut a = h_ciphertext.inner.get(0).unwrap().clone();
        let mut b = h_ciphertext.inner.get(1).unwrap().clone();
        let mut c = h_ciphertext.inner.get(2).unwrap().clone();
        let mut d = h_ciphertext.inner.get(3).unwrap().clone();
        let mut e = h_ciphertext.inner.get(4).unwrap().clone();
        let mut f = h_ciphertext.inner.get(5).unwrap().clone();
        let mut g = h_ciphertext.inner.get(6).unwrap().clone();
        let mut h = h_ciphertext.inner.get(7).unwrap().clone();
        let mut ch_val: FheUint32;

        for i in 0..64 {
            ch_val = ch(e.clone(),f.clone(),g.clone());
            t_1 = h.clone() + capsigma_one(e.clone()) + ch_val.clone() + k_ciphertext.inner.get(i).unwrap().clone() + input_ciphertext.inner.get(i).unwrap().clone();
            t_2 = capsigma_zero(a.clone()) + maj(a.clone(),b.clone(),c.clone());
            h = g.clone();
            g = f.clone();
            f = e.clone();
            e = d.clone() + t_1.clone();
            d = c.clone();
            c = b.clone();
            b = a.clone();
            a = t_1.clone() + t_2.clone();
        }

        first_32 += a;
        second_32 += b;
        third_32 += c;
        fourth_32 += d;
        fifth_32 += e;
        sixth_32 += f;
        seventh_32 += g;
        eight_32 += h;

        for (elem, value) in h_ciphertext.inner.iter_mut().zip(
            [first_32.clone(), second_32.clone(), third_32.clone(), fourth_32.clone(), fifth_32.clone(), sixth_32.clone(), seventh_32.clone(), eight_32.clone()]
                .iter(),
        ) {
            *elem = value.clone();
        }

    }

    let vec_fin = vec![first_32, second_32, third_32, fourth_32, fifth_32, sixth_32, seventh_32, eight_32];


    let result = OutputSha256::decrypt_final(vec_fin, &client_key);

    OutputSha256::print_hex(&result);
    }

    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);

}

fn padded_input(input_message: &str) -> Vec<u32> {
    let bit_length: u64 = (input_message.as_bytes().len() as u64) * 8u64;

    let n = (bit_length + 64) / 512 + 1;

    let mut result = string_to_u32_vector(input_message);

    let size_u32 = ((n*16u64) as usize) - 2;


    for _i in result.len()..size_u32 {
        result.push(0u32);
    }

    let upper: u32 = (bit_length >> 32) as u32;
    let lower: u32 = bit_length as u32;

    result.push(upper);
    result.push(lower);


    let mut eight_bits = split_into_8bit_vector(&result.clone());


    replace_first_zero_byte(&mut eight_bits);

    let returned = vec_u8_to_u32(&eight_bits);

    // print_u32_binary(&returned);
    returned
}


fn ch(x: FheUint32, y: FheUint32, z: FheUint32) -> FheUint32 {
    (x.clone() & y.clone()) ^ ((x.clone().neg() - 1u32) & z.clone())
}

fn maj(x: FheUint32, y: FheUint32, z: FheUint32) -> FheUint32 {
    (x.clone() & y.clone()) ^ (x.clone() & z.clone()) ^ (y.clone() & z.clone())
}

fn capsigma_zero(x: FheUint32) -> FheUint32 {
    rotate_right(x.clone(),2) ^ rotate_right(x.clone(),13) ^ rotate_right(x.clone(),22) 
}

fn capsigma_one(x: FheUint32) -> FheUint32 {
    rotate_right(x.clone(),6) ^ rotate_right(x.clone(),11) ^ rotate_right(x.clone(),25)
}

fn sigma_zero(x: FheUint32) -> FheUint32 {
    rotate_right(x.clone(),7) ^ rotate_right(x.clone(),18) ^ (x.clone() >> 3u32)
}


fn sigma_one(x: FheUint32) -> FheUint32 {
    rotate_right(x.clone(),17) ^ rotate_right(x.clone(),19) ^ (x.clone() >> 10u32)
}


fn rotate_right(x: FheUint32, amount: u32) -> FheUint32 {
    (x.clone() >> amount) | (x.clone() << (32u32 - amount))
}

// Chat-GPT generated helper functions

fn string_to_u32_vector(s: &str) -> Vec<u32> {
    let mut result = Vec::new();
    let bytes = s.as_bytes();

    for i in (0..bytes.len()).step_by(4) {
        let slice_end = std::cmp::min(i + 4, bytes.len());
        let bytes_slice = &bytes[i..slice_end];
        let mut value_bytes = [0u8; 4];
        value_bytes[..bytes_slice.len()].copy_from_slice(bytes_slice);
        let value = u32::from_be_bytes(value_bytes);
        result.push(value);
    }

    result
}

fn split_into_8bit_vector(vec: &Vec<u32>) -> Vec<u8> {
    let mut result = Vec::new();
    for value in vec.iter() {
        for i in 0..4 {
            result.push(((value >> (24 - i * 8)) & 0xFF) as u8);
        }
    }
    result
}

fn replace_first_zero_byte(vec: &mut Vec<u8>) {
    for byte in vec.iter_mut() {
        if *byte == 0 {
            *byte = 0b10000000;
            break;
        }
    }
}

fn vec_u8_to_u32(input: &[u8]) -> Vec<u32> {
    assert_eq!(input.len() % 4, 0, "Input length must be a multiple of 4");
    let mut output = Vec::with_capacity(input.len() / 4);
    for i in (0..input.len()).step_by(4) {
        let byte_slice = &input[i..i + 4];
        let mut bytes = [0u8; 4];
        bytes[..byte_slice.len()].copy_from_slice(byte_slice);
        let value = u32::from_be_bytes(bytes);
        output.push(value);
    }
    output
}

fn print_u32_binary(v: &Vec<u32>) {
    for value in v.iter() {
        println!("{:032b}", value);
    }
}
