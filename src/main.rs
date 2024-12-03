
#![allow(warnings)]
use std::io::Write;
use std::{fs::File,io, ptr::null};
mod enums;
use enums::{Kyber_Category, RNG_Category};
use random_number_generation::{RngOutput, RngType};
mod kyber;
mod key_generation;
mod helping_functions;
mod random_number_generation;


// Main facade method
use std::{env, vec};

fn main() {
    let args: Vec<String> = env::args().collect();

    // 1. Check if any arguments are provided
    if args.len() == 1 {
        println!("No arguments provided. Use --help or -h for usage information.");
        return;
    }

    let mut security_level: Option<u8> = None;
    let mut mode: Option<&str> = None; // "enc" for encapsulation, "dec" for decapsulation
    let mut key_file: Option<String> = None;
    let mut use_own_key: bool = false;
    let mut quick_encaps_decaps = 0;// 0 not set 1 => E2, 2=>E3 3=> E5     4 => D2, 5=>D3, 6=> D5

    // Parse arguments
    let mut i = 1;
    let mut args_iter = args.iter().skip(1); // Skip the program name

    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--version" | "-v" => {
                println!("My Program Version 1.0");
                return;
            }
            "--sec" | "-s" => {
                if let Some(sec_arg) = args.get(i + 1) {
                    if let Ok(sec) = sec_arg.parse::<u8>() {
                        if [2, 3, 5].contains(&sec) {
                            security_level = Some(sec);
                        } else {
                            println!("Invalid security level. Use 2, 3, or 5.");
                            return;
                        }
                    } else {
                        println!("Invalid security level value. It must be a number.");
                        return;
                    }
                    i += 1; // Skip the next argument as it is the value for --sec
                } else {
                    println!("Missing value for --sec or -s.");
                    return;
                }
            }
             // Handle quick use modes
             _ if args[i].starts_with("-E") || args[i].starts_with("-D") => {
                if mode.is_some() {
                    println!("Both encapsulation (-E<number>) and decapsulation (-D<number>) cannot be specified together. Or with --enc, -e / --dec, -d");
                    return;
                }
            
                let (prefix, num_str) = args[i].split_at(2); // Split into "-E"/"-D" and the number
                if let Ok(num) = num_str.parse::<u8>() {
                    if num == 2 || num == 3 || num == 5 {
                        // Determine if it's encapsulation or decapsulation
                        let is_encaps = prefix == "-E"; 
                        let mode_type = if is_encaps { "enc" } else { "dec" };
            
                        // Save the number and mode
                        mode = Some(mode_type);
                        security_level = Some(num);
            
                        use_own_key = false;
            
                        // Check for --key-file or -f in remaining args
                        let mut args_iter = args[i + 1..].iter();
            
                        while let Some(arg) = args_iter.next() {
                            match arg.as_str() {
                                "--key-file" | "-f" => {
                                    if let Some(file_arg) = args_iter.next() {
                                        key_file = Some(file_arg.to_string());
                                    } else {
                                        println!("Expected a file name after {}.", arg);
                                        return;
                                    }
                                    break;
                                }
                                _ => {}
                            }
                        }
                    } else {
                        println!("Invalid number for {}. Allowed values are 2, 3, or 5.", prefix);
                        return;
                    }
                } else {
                    println!("Invalid argument: {}. Expected format: -E<number> or -D<number>.", args[i]);
                    return;
                }
            }
            "--enc" | "-e" => {
                if mode.is_some() {
                    println!("Both encapsulation (--enc) and decapsulation (--dec) cannot be specified together.");
                    return;
                }
                mode = Some("enc");
            }
            "--dec" | "-d" => {
                if mode.is_some() {
                    println!("Both encapsulation (--enc) and decapsulation (--dec) cannot be specified together.");
                    return;
                }
                mode = Some("dec");
            }
            "--key-file" | "-f" => {
                if let Some(file_arg) = args.get(i + 1) {
                    key_file = Some(file_arg.to_string());
                    i += 1; // Skip the next argument as it is the value for --key-file
                } else {
                    println!("Missing value for --key-file or -f.");
                    return;
                }
            }
            "--own-key" | "-o" => {
            if key_file.is_none() {
                // Check if --key-file was provided
                println!("Error: --own-key or -o requires --key-file or -f to be specified first.");
                return;
            }
            else {
                use_own_key = true;
            }

        }
            other => println!("Unrecognized argument: {}", other),
        }
        i += 1;
    }


    let file_path_clone = key_file.clone();

    // 2. Check if --sec or -s is provided
    if security_level.is_none() {
        println!("Error: Security level (--sec or -s) is required.");
        return;
    }
    let mut strength: u32 = 0;
    let mut kyber =  match security_level
        {

            Some(2) => kyber::kyber::Kyber::create(2),
            Some(3) => kyber::kyber::Kyber::create(3), 
            Some(5) => kyber::kyber::Kyber::create(4),
            Some(_) => panic!("Invalid security level! Quitting!"),
            None => panic!("No security level! Quitting!")
        };

    kyber::set_env_vars(kyber.params.clone());

    // 3. Check if either --enc or --dec is specified
    if mode.is_none() {
        println!("Error: You must specify either --enc or --dec.");
        return;
    }

    // 4. Handle mode-specific requirements
    match mode.unwrap() {
        "enc" => {
            println!("Encapsulation mode selected.");
            if let Some(file) = key_file {
                println!("Key file specified: {}", file);
            } else {
                panic!("Keyfile required! Quitting!")
            }
        }
        "dec" => {
            println!("Decapsulation mode selected.");
            if key_file.is_none() {
                println!("Error: Key file (--key-file or -f) is required for decapsulation.");
                return;
            }
            println!("Key file specified: {}", key_file.unwrap());
        }
        _ => unreachable!(),
    }

    println!("Security level: {}", security_level.unwrap());
    println!("Performing requested operation:");

    
    if mode == Some("enc") {
        seed_rng();
        encapsulate_short(use_own_key, file_path_clone, security_level);
    }
    
    else if mode == Some("dec")
    {
        decapsulate_short( file_path_clone, security_level);
    }
    else {
        panic!("Unable to encrypt!");
    }
}
fn seed_rng()
{
    let mut rng = crate::kyber ::GLOBAL_RANDOM.lock().unwrap();
    match random_number_generation::generate_random_vector(RngType::Os, (0u8, 255u8), 48) {
        RngOutput::Vector(random_values) => {
            rng.randombytes_init(random_values, None, 256);
        }
        _ => {
            panic!("Could not seed RNG!");
        }
    }
}
fn decapsulate_short(file_path_clone:Option<String>, security_level:Option<u8>)
{
    let mut file: Option<File> = None;
    let file_path = file_path_clone.as_ref().unwrap();
    let file_path_trimmed = file_path.trim();

    
        // Attempt to open the file
        file = Some(File::open(file_path_trimmed).unwrap_or_else(|err| {
            panic!("Failed to open file at '{}': {}", file_path_trimmed, err);
        }));

        let mut doskippub = false;
        let mut doskipss = false;

        // Read the public key from the file
        let mut public_key = None; // Initialize public_key as None
        match helping_functions::helping_functions::read_hex_from_file_after_keyword(
            &mut file.as_mut().unwrap(),
            "public key:",)
            {
                Ok(value) => {
                    public_key = Some(value); 
                }
                Err(err) => {
                    println!("No public key");
                    doskippub = true; 
                }
            }
        
        let mut private_key = Some(
            helping_functions::helping_functions::read_hex_from_file_after_keyword(
                &mut file.as_mut().unwrap(),
                "private key:",
            )
            .unwrap_or_else(|err| panic!("No private key, cannot continue!: {}", err)),
        );

        let mut ss = None; // Initialize public_key as None
        match helping_functions::helping_functions::read_hex_from_file_after_keyword(
            &mut file.as_mut().unwrap(),
            "shared secret:",)
            {
                Ok(value) => {
                    ss = Some(value); 
                }
                Err(err) => {
                    println!("No shared secret, will not compare");
                    doskipss = true; 
                }
            }
        let mut ciphertext = Some(
            helping_functions::helping_functions::read_hex_from_file_after_keyword(
                &mut file.as_mut().unwrap(),
                "ciphertext:",
            )
            .unwrap_or_else(|err| panic!("No ciphertext, cannot continue!: {}", err)),
        );

        let mut pub_key = vec![0u8;1];
        let mut share_secret = vec![0u8;1];
        let mut priv_key = vec![0u8;1];
        let mut cipher_text= vec![0u8;1];
        if public_key.is_none() || doskippub
        {
            pub_key = vec![0u8;1];
        }
        else {
            pub_key = public_key.unwrap();
        }

        if !private_key.is_none()
        {
            priv_key = private_key.as_ref().unwrap().to_vec();
            if priv_key.is_empty() || priv_key.iter().all(|&x| x == 0) {
                panic!("Invalid private key! Quitting!.");
            }

        }
        else {
            panic!("Private key was empty! Quitting!")
        }
        if ss.is_none() || doskipss
        {
            share_secret = vec![0u8;1];
        }
        else {
            share_secret = ss.clone().unwrap();
        }
        if !ciphertext.is_none()
        {
            cipher_text = ciphertext.as_ref().unwrap().to_vec();
            if cipher_text.is_empty() || cipher_text.iter().all(|&x| x == 0) {
                println!("Invalid public key.");
            }

        }
        else {
            panic!("Ciphertext was empty! Quitting!");
        }

    // Open file and truncate it for writing
    file = Some(File::create(file_path_trimmed).unwrap_or_else(|err| {
        panic!("Failed to create/truncate file at '{}': {}", file_path_trimmed, err);
    }));
    let mut new_ss = vec![0u8; 32];
    let file = file.as_mut().unwrap();
    // Write keys to file
    writeln!(file, "PRIVATE KEY: '{}'", hex::encode(&priv_key))
        .expect("Failed to write private key to file");
    writeln!(file, "PUBLIC KEY: '{}'", hex::encode(&pub_key))
        .expect("Failed to write public key to file");

    // Perform decapsulation

    if kyber::kem::kem::crypto_kem_dec(&mut new_ss,  &mut cipher_text, &mut priv_key).is_ok() {
        println!("Decapsulation Completed!");
        println!("Please see file for keys.");
        println!("Ciphertext: {}", hex::encode(&cipher_text));
        println!("Shared Secret: {}", hex::encode(&new_ss));
        if share_secret != vec![0u8;1]
        {
           
            if share_secret == new_ss
            {
                println!("Both shared secrets match!");
            }
            else {
                eprintln!("BOTH SHARED SECRETS DO NOT MATCH!");
            }
        }

        writeln!(file, "Ciphertext: '{}'", hex::encode(&cipher_text))
            .expect("Failed to write ciphertext to file");
        writeln!(file, "Shared Secret: '{}'", hex::encode(&new_ss))
            .expect("Failed to write shared secret to file");
    } else {
        panic!("Encapsulation Failed");
    }
}

fn encapsulate_short(use_own_key:bool, file_path_clone:Option<String>, security_level:Option<u8>)
{
    let mut public_key = None;
    let mut file: Option<File> = None;
    let file_path = file_path_clone.as_ref().unwrap();
    let file_path_trimmed = file_path.trim();

    
    let mut private_key = match security_level {
        Some(2) => vec![0u8; 1632],
        Some(3) => vec![0u8; 2400],
        Some(5) => vec![0u8; 3168],
        Some(_) => {
            panic!("Invalid security level detected!");
        },
        None => {
            panic!("No security level detected!");
        },
    };
    let mut ciphertext = match security_level {
        Some(2) => vec![0u8; 768],
        Some(3) => vec![0u8; 1088],
        Some(5) => vec![0u8; 1568],
        Some(_) => {
            panic!("Invalid security level detected!");
        },
        None => {
            panic!("No security level detected!");
        },
    };

    if use_own_key {
        // Attempt to open the file
        file = Some(File::open(file_path_trimmed).unwrap_or_else(|err| {
            panic!("Failed to open file at '{}': {}", file_path_trimmed, err);
        }));

        // Read the public key from the file
        public_key = Some(
            helping_functions::helping_functions::read_hex_from_file_after_keyword(
                &mut file.as_mut().unwrap(),
                "public key:",
            )
            .unwrap_or_else(|err| panic!("Error reading public key: {}", err)),
        );

        let pk = public_key.as_ref().unwrap();
        if pk.is_empty() || pk.iter().all(|&x| x == 0) {
            panic!("Invalid public key! Quitting!");
        }

    } 
    else {


        // Generate public key based on security level
        public_key = Some(match security_level {
            Some(2) => vec![0u8; 800],
            Some(3) => vec![0u8; 1184],
            Some(5) => vec![0u8; 1568],
            _ => panic!("Invalid security level detected!"),
        });                
        // Generate the private key
        if use_own_key
        {

                helping_functions::helping_functions::do_key_generation(
                1,
                &mut public_key.as_mut().unwrap(),
                &mut private_key,
                true);
        }
        else
         {
                helping_functions::helping_functions::do_key_generation(
                1,
                &mut public_key.as_mut().unwrap(),
                &mut private_key,
                false);
        }
    }


    // Open file and truncate it for writing
    file = Some(File::create(file_path_trimmed).unwrap_or_else(|err| {
        panic!("Failed to create/truncate file at '{}': {}", file_path_trimmed, err);
    }));

    let file = file.as_mut().unwrap();
    // Write keys to file
    writeln!(file, "PRIVATE KEY: '{}'", hex::encode(&private_key))
        .expect("Failed to write private key to file");
    writeln!(file, "PUBLIC KEY: '{}'", hex::encode(public_key.as_ref().unwrap()))
        .expect("Failed to write public key to file");

    // Perform encapsulation
    let mut ss: Vec<u8> = vec![0u8; 32];
    let mut ciphertext = match security_level {
        Some(2) => vec![0u8; 768],
        Some(3) => vec![0u8; 1088],
        Some(5) => vec![0u8; 1568],
        _ => panic!("Invalid security level detected!"),
    };

    let pk = public_key.as_mut().unwrap();
    if kyber::kem::kem::crypto_kem_enc(&mut ciphertext, &mut ss, pk).is_ok() {
        println!("Encapsulation Completed!");
        println!("Please see file for keys.");
        println!("Ciphertext: {}", hex::encode(&ciphertext));
        println!("Shared Secret: {}", hex::encode(&ss));

        writeln!(file, "Ciphertext: '{}'", hex::encode(&ciphertext))
            .expect("Failed to write ciphertext to file");
        writeln!(file, "Shared Secret: '{}'", hex::encode(&ss))
            .expect("Failed to write shared secret to file");
    } else {
        panic!("Encapsulation Failed");
    }
}

fn parse_argument<T: std::str::FromStr>(
    args_iter: &mut std::slice::Iter<String>,
    option_name: &str,
) -> Option<T> {
    if let Some(value) = args_iter.next() {
        if let Ok(parsed) = value.parse::<T>() {
            Some(parsed)
        } else {
            println!("Invalid value for {}: {}", option_name, value);
            None
        }
    } else {
        println!("Missing value for {}", option_name);
        None
    }
}


fn print_help() {
    println!("Please note that many terminals have input restrictions on length. As such for decapsulation mode please supply keys in a seperate file. the format is demonstrated below:");
    println!("Order does not matter, for decapsulation only private key and ciphertext are required. If you would like to validate the shared secret, include it in the file and the program will alert to a match");
    println!("This is also the format that the program will output in encapsulation mode.");
    println!("PRIVATE KEY: '<HEX VALUE>'");
    println!("PUBLIC KEY: '<HEX VALUE>'");
    println!("Ciphertext: '<HEX VALUE>'");
    println!("Shared Secret: '<HEX VALUE>'");
    println!("Encapsulation mode does not require any input. However, you can supply your own key if you wish.");
    println!("Your output will be saved in the keyfile provided.");

    println!("Usage: my_program [options]");
    println!("Options:");
    println!("  --help, -h     Show this help message");
    println!("\n~~~For Encapsulation Mode~~~");
    println!("  --sec,                       -s   Security level selection: 2,3 or 5");
    println!("  --enc,                       -e   Encapsulation mode");
    println!("  --key-file <file path>,      -f   Use keyfile");
    println!("  --own-key                    -o   Use own public key");
  
    println!("example use for using own key:");
    println!("./kyber --sec 5 --enc --key-file /home/my_output/kyber_output --own-key  ");
    println!("Alternatively:");
    println!("./kyber -s 5 -e -f /home/my_output/kyber_output -o");
    println!("\nQUICK USE");
    println!("You can use the following style of command to quickly run encapsulation with default settings.");
    println!("./kyber -E<security_level> /home/file_for_key");
    println!("e.g ./kyber -E5 /home/my_encapsulation");

    println!("Example input to use key generation:");
    println!("./kyber --sec 3 --enc --key-file /home/my_output/kyber_output ");
    println!("Alternatively:");
    println!("./kyber -s 3 -e -f /home/my_output/kyber_output ");

    println!("\n~~~For Decapsulation Mode~~~");
    println!("  --sec,                       -s   Security level selection: 2,3 or 5");
    println!("  --dec,                       -d   Decapsulation mode");
    println!("  --key-file <file path>,      -f   Use keyfile");
    println!("Example input to decapsulate:");
    println!("./kyber --sec 3 --dec --key-file /home/my_output/kyber_output ");
    println!("Alternatively:");
    println!("./kyber -s 3 -d -f /home/my_output/kyber_output");
    println!("\nQUICK USE");
    println!("You can use the following style of command to quickly run decapsulation with default settings.");
    println!("./kyber -D<security_level> /home/file_for_key");
    println!("e.g ./kyber -D5 /home/my_decapsulation");

    println!("Options for security level");
    println!("  2                             Kyber 512 ");
    println!("  3                             Kyber 768 ");
    println!("  5                             Kyber 1024 ");
}

fn call_kyber()
{
    let mut category_choice: u32  = 0;
    let strength = list_types_and_strengths_kyber();
    loop {
            println!("Would you like to:");
            println!("1. Generate an output from which a shared secret may be derived.");
            println!("in this mode you can generate or enter your own keys to derive a ciphertext from which a shared secret may be extracted.");
            println!("\n2. You can use a private key along with a cipher text to derive a shared secret.");
            println!("If you are confirming a shared secrtet, you can optionally include your already derived shared secret in an input file and the function will alert if there is a match.");
            println!("0. Return to previous menu");
            let mut input = String::new();
            io::stdin().read_line(&mut input);
            category_choice = input.trim().parse().unwrap_or(1001);
            if category_choice == 1001{
                println!("Sorry, no input was provided. Please try again.");
                continue; 
            }
            match category_choice
            {
                1 => break,
                2 => break,
                0 => return,
                _ => println!("Sorry, I didnt understand that\nPlease try again")
            }
        }
        if category_choice == 1
        {
            kyber::encapsulate_long(Some(strength));
        }
        else if category_choice == 2
        {
            kyber::decapsulate_long();
        }
        else {
            eprintln!("Something is going wrong with the mode selection!\nReturning...");
            return;
        } 

}
// Kyber Key Encapsulation
fn list_types_and_strengths_kyber() -> Kyber_Category {
    println!("Kyber Key Encapsulation Strengths");
    println!("Please select the strength required");
    println!("Please enter the whole text or the number");
    let mut should_break = false;
    let mut return_category = Kyber_Category::Kyber512;
    loop {
        println!("Select a category:");
        println!("1. Kyber512 (PK is 800 bits SK is 1,128 bits and CT is 736 bits");
        println!("2. Kyber768 (PK is 1,184 bits SK is 1,648 bits and CT is 1,080 bits");
        println!("3. Kyber1024 (PK is 1,556 bits SK is 2,080 bits and CT is 1,440 bits");
        println!("0. Return to Previous Menu");
        // Read user input
        let mut input = String::new();
        io::stdin().read_line(&mut input);
        let category_choice: u32 = input.trim().parse().unwrap_or(1001);
        if category_choice == 1001{
            println!("Sorry, no input was provided. Please try again.");
            continue; 
        }

        match category_choice {
            1 => { return_category = Kyber_Category::Kyber512; should_break = true; },
            2 => { return_category = Kyber_Category::Kyber768; should_break = true; },
            3 => { return_category = Kyber_Category::Kyber1024; should_break = true; },
            0 => { return_category = Kyber_Category::Exit; should_break = true; },
            _ => {
                println!("Sorry, that was an invalid choice!\nPlease try again.");
                should_break = false;
            }
        }
    
        if should_break {
            break;
        }
    }
    return_category

}
