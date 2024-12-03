#![allow(warnings)]
use std::{env, fs, u8};
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::io;
use std::io::prelude::*;
use std::fs::File;
use std::path::Path;
use libloading::{Library, Symbol};
use std::ptr;
use lazy_static::lazy_static;

extern crate sha2;
use std::sync::Mutex;
use std::io::{BufRead, Read};
use std::io::{Write};
use crate::enums::Kyber_Category;
use crate::key_generation;
pub(crate) mod kem;
pub(crate) mod kyber;
mod xof_state;
mod kyber_rng;
mod speed_print;
use crate::helping_functions;
mod config;
mod fips202;
mod indcpa;
mod aes256ctr;
mod symmetric_aes;
mod polyvec;
mod verify;
mod poly_struct;
mod polyvec_struct;
mod poly;
mod cbd;
mod reduce;
mod ntt;
mod symmetric_shake;
use crate::random_number_generation;

lazy_static! {
    pub static ref GLOBAL_RANDOM: Mutex<kyber_rng::KyberRng> = Mutex::new(kyber_rng::KyberRng::new());
}

pub fn first_welcome()
{

    println!("Welcome to Rl-Encrypts Kyber Module!");
    println!("Kyber is a post-quantum cryptographic algorithm designed to provide secure key encapsulation mechanism (KEM)");
    println!("It is one of the candidates submitted to the NIST Post-Quantum Cryptography
                Standardization Project.\nIt is used for securely encapsulating symmetric keys.");
}
pub fn encapsulate_long(cat:Option<Kyber_Category>) {
    println!("You have selected to encapsulate information");
    helping_functions::helping_functions::seed_rng(None);

    let mut strength: u32 = 0;
    if cat.is_some()
    {
        match cat
        {
            Some(cat_out) => {
              strength =  match cat_out
                {
                    Kyber_Category::Kyber512 => 2,
                    Kyber_Category::Kyber768 => 3,
                    Kyber_Category::Kyber1024 => 4,
                    Kyber_Category::Exit => 0,
                }
            },
            None => strength = 0,
        }
    }
    else
    {
        println!("Please enter the security strength, you can always adjust it later.");
        strength = helping_functions::helping_functions::get_security_strength();
    }
    if strength == 0
    {
        eprintln!("Strength was 0!!\nSomething went wrong...\nReturning...");
        return;
    }
    let mut kyber = kyber::Kyber::create(strength);
    set_env_vars(kyber.params.clone());

    let mut file = loop {
        println!("Please enter the file path where you would like to save the key information:");
        let mut file_path = String::new();
        io::stdin().read_line(&mut file_path).expect("Failed to read line");
        let file_path = file_path.trim();

        match File::create(file_path) {
            Ok(file) => break file,
            Err(_) => println!("Failed to create file. Please try again."),
        }
    };

    let mut private_key = vec![0u8; kyber.params.kyber_secretkeybytes as usize];
    let mut public_key = vec![0u8; kyber.params.kyber_publickeybytes as usize];
    let mut keep_loop = true;
    while keep_loop
    {
        println!("Do you have a key (not recommended) or would you like to generate one?");
        println!("Please enter 'gen' or 'enter'");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read line");
        let sel = input.trim().to_ascii_lowercase();

        if sel == "gen" {
            helping_functions::helping_functions::get_keys_generated(&mut public_key, &mut private_key);
            keep_loop = false;
        } 
        else if sel == "enter" 
        {
        loop {
            println!("Due to arbitrary limits on string litterals in Rust, you need to use a file to enter the keys");
            let mut file_path = "".to_owned();
            loop {

                    println!("Please enter the path to the file containing private key and secret key:");
                
                    io::stdin().read_line(&mut file_path);
                    let file_path = file_path.trim();
            
                    match File::open(&file_path) {
                        Ok(f) => {
                            file = f;
                            break;
                        },
                        Err(_) => {
                            println!("Failed to open file. Please try again.");
                        }
                    }
                }
                    let mut is_error:bool = false;
                    private_key = read_hex_from_file_after_keyword(&mut file, "private key:").expect("Error converting private key to hex");
                    public_key = read_hex_from_file_after_keyword(&mut file, "public key:").expect("Error converting public key to hex");
            
                    if private_key.is_empty() || private_key.iter().all(|&x| x == 0) 
                    {
                        println!("Error with private key");
                        is_error = true;
                    }
                    
                    // Check if ciphertext is null or all zeros
                    if public_key.is_empty() || public_key.iter().all(|&x| x == 0) 
                    {
                        println!("Error with public key");
                        is_error = true;
                    }
            
                    if is_error
                    {
                        println!("Sorry, either private key or public key could not be read properly. Please try again with a new file!")
                    }
                    else 
                    {
                        keep_loop = false;
                        break;
                    }
                    let pub_len = kyber.params.kyber_publickeybytes;
                    let priv_len = kyber.params.kyber_secretkeybytes;
                    if public_key.len() == pub_len as usize && private_key.len() == priv_len as usize 
                    {
                        keep_loop = false;
                        break;
                    }
                    else {
                        println!("Error with key length, please try again!");
                    }
            }
        }
        else 
        {
            println!("Sorry I didn't understand, please try again!");
        }
    }
    // Display keys in hex format on console
    println!("PRIVATE KEY: {}", hex::encode(&private_key));
    println!("PUBLIC KEY: {}", hex::encode(&public_key));
    
    // Save keys to file in hex format
    writeln!(file, "PRIVATE KEY: '{}'", hex::encode(&private_key)).expect("Failed to write to file");
    writeln!(file, "PUBLIC KEY: '{}'", hex::encode(&public_key)).expect("Failed to write to file");

    // Kyber encapsulation
    let mut cc: Vec<u8> = vec![0u8; kyber.params.kyber_ciphertextbytes as usize];
    let mut ss: Vec<u8> = vec![0u8; kyber.params.kyber_ssbytes as usize];
    let mut nothing = String::new();
    if kem::kem::crypto_kem_enc(&mut cc, &mut ss, &mut public_key).is_ok() {
        println!("Encapsulation Completed");
        println!("Ciphertext: {}", hex::encode(&cc));
        println!("Shared Secret: {}", hex::encode(&ss));

        // Save encapsulated data to file
        writeln!(file, "Ciphertext: '{}'", hex::encode(&cc)).expect("Failed to write to file");
        writeln!(file, "Shared Secret: '{}'", hex::encode(&ss)).expect("Failed to write to file");

       
    } else {
        println!("Encapsulation Failed");
    }
    println!("Press return to continue...");
    io::stdin().read_line(&mut nothing);
}
fn read_hex_from_file_after_keyword(file: &mut File, keyword: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    file.seek(io::SeekFrom::Start(0))?; 
    let buf_reader = io::BufReader::new(&*file);
    let lines = buf_reader.lines();

    for line in lines {
        let line = line?;
        if line.to_ascii_lowercase().contains(keyword) {
            // Extract the hex value enclosed in single quotes
            if let Some(start) = line.find('\'') {
                if let Some(end) = line[start+1..].find('\'') {
                    let hex_string = &line[start+1..start+1+end];
                    return hex::decode(hex_string.trim()).map_err(|e| e.into());
                }
            }
        }
    }

    Err("Keyword not found or no data after keyword".into())
}

pub fn decapsulate_long() -> Result<(), Box<dyn std::error::Error>> {

    let mut private_key;
    let mut ss;
    let mut ciphertext;
    loop {

    println!("You have selected to decapsulate information.");
    let mut file; 
    let mut file_path = String::new();
    loop {

        println!("Please enter the path to the file containing private key, shared secret, and ciphertext:");
       
        io::stdin().read_line(&mut file_path)?;
        let file_path = file_path.trim();

        match File::open(&file_path) {
            Ok(f) => {
                file = f;
                break;
            },
            Err(_) => {
                println!("Failed to open file. Please try again.");
            }
        }
    }
        let mut is_error:bool = false;
        private_key = read_hex_from_file_after_keyword(&mut file, "private key:")?;
        ss = read_hex_from_file_after_keyword(&mut file, "shared secret:")?;
        ciphertext = read_hex_from_file_after_keyword(&mut file, "ciphertext:")?;

        if private_key.is_empty() || private_key.iter().all(|&x| x == 0) {
            println!("Error with private key");
            is_error = true;
        }
        
        // Check if ciphertext is null or all zeros
        if ciphertext.is_empty() || ciphertext.iter().all(|&x| x == 0) {
            println!("Error with ciphertext");
            is_error = true;
        }

        if is_error
        {
            println!("Sorry, either private key or ciphertext could not be read properly. Please try again with a new file!")
        }
        else {
            break;
        }
    }

    if private_key.len() == 1632
    {
        let mut kyber = kyber::Kyber::create(2);
    set_env_vars(kyber.params.clone());
    }
    else if private_key.len() == 2400
    {
        let mut kyber = kyber::Kyber::create(3);
        set_env_vars(kyber.params.clone());
    }
    else if private_key.len() == 3168
    {
        let mut kyber = kyber::Kyber::create(4);
        set_env_vars(kyber.params.clone());
    }
    else {
        panic!("Something has gone very wrong with the private key input.");
    }
    let pkb:usize =  get_env_var("KYBER_CIPHERTEXTBYTES").unwrap();
    let skb:usize =get_env_var("KYBER_SSBYTES").unwrap();
    let mut cc: Vec<u8> = vec![0u8; pkb];
    let mut ss_new: Vec<u8> = vec![0u8; skb ];
    let mut nothing = String::new();
    println!("Performing decapsulation...");
    if kem::kem::crypto_kem_dec(&mut ss_new, &ciphertext, &private_key).is_ok() {
        println!("Decapsulation Completed");
         if ss_new.len() >1
         {
            if ss == ss_new
            {
                println!("Generated Secret: {}", hex::encode(ss_new));
                println!("Both shared secrets match!");
                println!("Press return to continue...");
                io::stdin().read_line(&mut nothing);
                Ok(())
            }
            else
            {
                println!("Comparison Failed!\nSecrets DO NOT match!");
                println!("Press return to continue...");
                io::stdin().read_line(&mut nothing);
                return Err("Secrets don't match".into());
            }
         }
         else
         {
            println!("No shared secret to compare");
            println!("Derived Shared Secret: {:?}", hex::encode(ss));
            println!("Press return to continue...");
            io::stdin().read_line(&mut nothing);
            Ok(())
         }
       
   
    } else {
        println!("Decapsulation Failed");
        println!("Press return to continue...");
        io::stdin().read_line(&mut nothing);
        Err("Decapsulation Failed!".into())
    }
}

fn parse_file_content(content: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut private_key = Vec::new();
    let mut shared_secret = Vec::new();
    let mut ciphertext = Vec::new();

    let sections = content.split("\n\n").collect::<Vec<_>>();

    for section in sections {
        if section.contains("PRIVATE KEY: ") {
            if let Some(priv_key) = section.split("PRIVATE KEY: ").nth(1) {
                private_key = hex::decode(priv_key.trim()).unwrap_or(Vec::new());
            }
        } else if section.contains("Shared Secret: ") {
            if let Some(ss) = section.split("Shared Secret: ").nth(1) {
                shared_secret = hex::decode(ss.trim()).unwrap_or(Vec::new());
            }
        } else if section.contains("Ciphertext: ") {
            if let Some(ct) = section.split("Ciphertext: ").nth(1) {
                ciphertext = hex::decode(ct.trim()).unwrap_or(Vec::new());
            }
        }
    }

    (private_key, shared_secret, ciphertext)
}

    fn output_to_file_hex(filename: &str, data: &[u8]) {
        let mut new_filename = String::from(filename);
        while Path::new(&new_filename).exists() {
            println!("File '{}' already exists. Do you want to delete it? (yes/no)", new_filename);
            let mut choice = String::new();
            io::stdin().read_line(&mut choice).expect("Failed to read line");
            let choice = choice.trim().to_ascii_lowercase();
            if choice == "yes" {
                fs::remove_file(&new_filename).expect("Failed to delete file");
                break;
            } else if choice == "no" {
                println!("Please enter a new name for the file:");
                let mut new_name = String::new();
                io::stdin().read_line(&mut new_name).expect("Failed to read line");
                new_filename = new_name.trim().to_string();
            } else {
                println!("Invalid choice. Please enter 'yes' or 'no'.");
            }
        }
        let mut file = File::create(&new_filename).expect("Failed to create file");
        file.write_all(hex::encode(data).as_bytes()).expect("Failed to write to file");
    }
    
    fn output_to_file_vector(filename: &str, data: &[u8]) {
        let mut new_filename = String::from(filename);
        while Path::new(&new_filename).exists() {
            println!("File '{}' already exists. Do you want to delete it? (yes/no)", new_filename);
            let mut choice = String::new();
            io::stdin().read_line(&mut choice).expect("Failed to read line");
            let choice = choice.trim().to_ascii_lowercase();
            if choice == "yes" {
                fs::remove_file(&new_filename).expect("Failed to delete file");
                break;
            } else if choice == "no" {
                println!("Please enter a new name for the file:");
                let mut new_name = String::new();
                io::stdin().read_line(&mut new_name).expect("Failed to read line");
                new_filename = new_name.trim().to_string();
            } else {
                println!("Invalid choice. Please enter 'yes' or 'no'.");
            }
        }
        let mut file = File::create(&new_filename).expect("Failed to create file");
        file.write_all(data).expect("Failed to write to file");
    }
pub fn set_env_vars(params: kyber::KyberParams)
{
    env::set_var("KYBER_K", params.kyber_k.to_string());
    env::set_var("KYBER_90S", "false");
    env::set_var("KYBER_NAMESPACE", params.kyber_namespace);
    env::set_var("KYBER_N", params.kyber_n.to_string());
    env::set_var("KYBER_Q", params.kyber_q.to_string());
    env::set_var("KYBER_SYMBYTES", params.kyber_symbytes.to_string());
    env::set_var("KYBER_SSBYTES", params.kyber_ssbytes.to_string());
    env::set_var("KYBER_POLYBYTES", params.kyber_polybytes.to_string());
    env::set_var("KYBER_POLYCOMPRESSEDBYTES", params.kyber_polycompressedbytes.to_string());
    env::set_var("KYBER_POLYVECBYTES", params.kyber_polyvecbytes.to_string());
    env::set_var("KYBER_ETA1", params.kyber_eta1.to_string());
    env::set_var("KYBER_POLYVECCOMPRESSEDBYTES", params.kyber_polyveccompressedbytes.to_string());
    env::set_var("KYBER_ETA2", params.kyber_eta2.to_string());
    env::set_var("KYBER_INDCPA_MSGBYTES", params.kyber_indcpa_msgbytes.to_string());
    env::set_var("KYBER_INDCPA_PUBLICKEYBYTES", params.kyber_indcpa_publickeybytes.to_string());
    env::set_var("KYBER_INDCPA_SECRETKEYBYTES", params.kyber_indcpa_secretkeybytes.to_string());
    env::set_var("KYBER_INDCPA_BYTES", params.kyber_indcpa_bytes.to_string());
    env::set_var("KYBER_PUBLICKEYBYTES", params.kyber_publickeybytes.to_string());
    env::set_var("KYBER_SECRETKEYBYTES", params.kyber_secretkeybytes.to_string());
    env::set_var("KYBER_CIPHERTEXTBYTES", params.kyber_ciphertextbytes.to_string());
}

pub fn get_env_var<T>(name: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    match env::var(name) {
        Ok(value) => match value.parse() {
            Ok(parsed) => Ok(parsed),
            Err(err) => Err(format!("Failed to parse {}: {:?}", name, err)),
        },
        Err(_) => Err(format!("{} environment variable not set", name)),
    }
}