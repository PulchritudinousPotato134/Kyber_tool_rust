use rand::{rngs::OsRng, Rng, RngCore, SeedableRng};
use std::convert::TryInto;
use sha2::{Sha256, Digest};
use hex;
use crate::enums::SecureKey_Category;

pub fn generate_one_osrng(size: usize) -> Vec<u8> {
    let seed_init = generate_two_pbkdf2(size as usize);
    let seed = stretch_seed(&seed_init);
    let mut os_rng = OsRng;

    let mut to_return: Vec<u8> = vec![0u8; size];

    os_rng.fill_bytes(&mut to_return);

    to_return
}
pub fn generate_two_pbkdf2(size: usize) -> Vec<u8> {
    let mut rand = rand_chacha::ChaChaRng::from_entropy();

    let mut toReturn: Vec<u8> = vec![0u8; size as usize];
    for i in 0..size {
        toReturn[i as usize] = rand.gen();
    }
    toReturn
}

fn stretch_seed(seed: &Vec<u8>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    let result = hasher.finalize();
    let mut stretched_seed = [0u8; 32];
    stretched_seed.copy_from_slice(&result[..]);
    stretched_seed
}

pub fn generate_iv(size: u8) -> String {
    let iv = generate_one_osrng(size.into());
    hex::encode(iv)
}

pub fn generate_key(keysize: usize) -> String {
    let mut start = std::time::Instant::now();
    let mut size = keysize;
    if keysize == 0
    {
        size = 32;
    }


    let mut key_part_i = generate_one_osrng((size as usize).try_into().unwrap());
    while key_part_i.len() < size {
        let remaining = size - key_part_i.len();
        key_part_i.extend_from_slice(&generate_one_osrng(remaining as usize));
    }
    key_part_i.truncate(size);


    let mut key_part_ii = generate_two_pbkdf2(size as usize);
    // Truncate or repeat key_part_ii to match the desired length
    while key_part_ii.len() < size {
        let remaining = size - key_part_ii.len();
        key_part_ii.extend_from_slice(&generate_two_pbkdf2(remaining as usize));
    }
    key_part_ii.truncate(size);


    let mut key_part_iii = Vec::new();
    let elapsed = start.elapsed();
    start = std::time::Instant::now();
    let microseconds = elapsed.as_micros();
    let non_zero_bytes: Vec<u8> = microseconds.to_le_bytes().iter().cloned().filter(|&x| x != 0).collect();
    key_part_iii.extend_from_slice(&non_zero_bytes);  


    while key_part_iii.len() < size {
        let remaining = size - key_part_ii.len();
        let elapsed = start.elapsed();
        start = std::time::Instant::now();
        let bytes: Vec<u8> = elapsed.as_micros().to_le_bytes().iter().cloned().filter(|&x| x != 0).collect();
        let microseconds_hash = stretch_seed(&bytes);
        key_part_iii.extend_from_slice(microseconds_hash.as_slice());
    }
    key_part_iii.truncate(size);


    let mut key: Vec<u8> = vec![0u8; size];
    for i in 0..size {
        key[i] = key_part_i[i] ^ key_part_ii[i] ^ key_part_iii[i];
    }

    hex::encode(key)
}


pub fn key_interface(cat:SecureKey_Category)
{
    match cat
    {
        SecureKey_Category::OsRng => 
        {
            let size = get_key_size();
            println!("Generating {} bit {} byte key...", size*8, size);
            let key = generate_one_osrng(size);
            println!("Key: {}", hex::encode(key));
        },
        SecureKey_Category::Pbkdf2 => {
            let size = get_key_size();
            println!("Generating {} bit {} byte key...", size*8, size);
            let key = generate_two_pbkdf2(size);
            println!("Key: {}", hex::encode(key));
        },
        SecureKey_Category::Combo => {
            let size = get_key_size();
            println!("Generating {} bit {} byte key...", size*8, size);
            let key = generate_key(size);
            println!("Key: {}", key);
        },
        SecureKey_Category::Exit => return,
    }
}

fn get_key_size() -> usize {
    loop {
        println!("Please enter the size for the key in bytes:");
        let mut input = String::new();

        // Read user input
        std::io::stdin().read_line(&mut input)
            .expect("Failed to read line");

        // Parse input into u32
        let key_size: usize = match input.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                println!("Invalid input. Please enter a valid number.");
                continue;
            }
        };

        println!("You entered key size: {}", key_size);
        println!("Is this correct? (yes/no)");

        let mut confirmation = String::new();
        std::io::stdin().read_line(&mut confirmation)
            .expect("Failed to read line");

        let confirmation = confirmation.trim().to_lowercase();

        if confirmation.contains("y") {
            return key_size;
        } else if confirmation.contains("n") {
            continue;
        } else {
            println!("Invalid response. Please enter 'yes' or 'no'.");
            continue;
        }
    }
}