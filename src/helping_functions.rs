pub mod helping_functions{
//TODO: Update comments for this
    use std::{fs::File, io::{self, BufRead, Seek}};


    pub fn ask_for_number_question_integer(question: &str) -> u32
    {
        loop {
            //Print question
            println!("{}", question);
            
            //create value
            let mut input = String::new();
            
            //read response
            io::stdin()
                .read_line(&mut input)
                .expect("Failed to read line");
    
            // Parse the input as a u32
            let parsed_input: Result<u32, _> = input.trim().parse();
            
            //verify
            match parsed_input {
                Ok(number) => {
                    return number;
                }
                Err(_) => {
                    println!("Invalid input. Please enter a valid number.");
                }
            }
        }
    }


    pub fn enter_a_password(correct_password: &str) -> i8 {
        let mut i = 3; 
    
        while i > 0 {
            println!("You have {} attempts", i);
            println!("Enter your password: ");
            
            let mut user_input = String::new();
            io::stdin().read_line(&mut user_input).expect("Failed to read input");
            
            let user_input = user_input.trim(); // Remove trailing newline
            if user_input.to_lowercase() == "l" || user_input.to_lowercase() == "leave"
                {
                    return 1;
                }
            if user_input == correct_password {
                return 0;
            }
            
            i -= 1; 
        }
    
        return -1;
    }
   
    

    pub fn get_security_strength() -> u32 {
        loop {
            println!("Choose a security strength (2, 3, or 4):");
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .expect("Failed to read line");

            // Parse the user's input as a u8
            match input.trim().parse::<u32>() {
                Ok(strength) => {
                    if [2, 3, 4].contains(&strength) {
                        return strength;
                    } else {
                        println!("Invalid input. Please enter 2, 3, or 4.");
                    }
                }
                Err(_) => {
                    println!("Invalid input. Please enter a number (2, 3, or 4).");
                }
            }
        }
    }
  
    pub fn get_keys_generated(mut public:&mut Vec<u8>, mut private:&mut Vec<u8>) {
        let mut input = String::new();
        let mut selected_number = 0;
        loop {
            println!("Please select your method of key generation all options are cryptographically secure");
            println!("Enter the relevant number.");
            println!("1. DRNG Based on AES-256");
            println!("2. Operating System RNG");
            println!("3. ChaChaRng");
            println!("4. Xored Combination");

            // Read user input
            io::stdin().read_line(&mut input).expect("Failed to read line");

            // Parse the input as a u32
            let parsed_input: Result<u32, _> = input.trim().parse();
            
            //verify
            match parsed_input {
                Ok(number) => {
                   selected_number = number;
                   break;
                }
                Err(_) => {
                    println!("Invalid input. Please enter a valid number.");
                }
            }
            
        }

        do_key_generation(selected_number, public, private, false);

       
    }

    pub fn do_key_generation(selected_number:u32, mut public:&mut Vec<u8>, mut private:&mut Vec<u8>, included_pub_key:bool)
    {
        let mut copy_pub_key = public.clone();

        match selected_number
        {
            1 => {
            if let Ok(()) = crate::kyber::kem::kem::crypto_kem_keypair(&mut public, &mut private) 
                {
                    println!("Key pair generated successfully.");
                }   
            },
            2 =>
            {
               let mut priv_res = crate::key_generation::generate_one_osrng(private.len());
               *private = priv_res;
               let mut pub_res = crate::key_generation::generate_one_osrng(public.len());
               *public = pub_res
            },
            3 =>
            {
                
               let mut priv_res = crate::key_generation::generate_two_pbkdf2(private.len());
               *private = priv_res;
               let mut pub_res = crate::key_generation::generate_two_pbkdf2(public.len());
               *public = pub_res;
            },
            4 =>
            {

               let mut priv_res = crate::key_generation::generate_key(private.len());
               *private = hex::decode(priv_res).expect("Failed to decode hex string");;
               let mut pub_res = crate::key_generation::generate_key(public.len());
               *public = hex::decode(pub_res).expect("Failed to decode hex string");
            },
            _ => {
                println!("Something has gone wrong, selection invalid");
            }
        }
        if included_pub_key {
            *public = copy_pub_key;
        }
    }
    pub fn seed_rng(personalisation_string: Option<Vec<u8>>) {
        let mut vec_out: Vec<u8> = Vec::with_capacity(50);
        
        let res = crate::random_number_generation::generate_random_vector(
            crate::random_number_generation::RngType::ChaCha20,
            (0u8, 255u8),
            48,
        );
    
        match res {
            crate::random_number_generation::RngOutput::Vector(data) => {
                vec_out.extend_from_slice(&data[0..48]);
            }
            _ => {
                panic!("Unexpected output type");
            }
        }
    
        let mut rng = crate::kyber::GLOBAL_RANDOM.lock().unwrap();
        if let Some(personalisation) = personalisation_string {
            rng.randombytes_init(vec_out, Some(personalisation), 256);
        } else {
            rng.randombytes_init(vec_out, None, 256);
        }
    }
    
pub fn is_valid_hex(input: &str) -> bool {
    if input.is_empty() {
        return false;
    }
    input.trim();
    let mut input_s:String = input.to_owned();
    
    // Manually remove newline characters (\n) from the end of the string
    while input_s.ends_with('\n') || input_s.ends_with('\r') {
        input_s.pop();
    }
    for c in input_s.chars() {
        if !c.is_ascii_hexdigit() {
            return false;
        }
    }

    true
}


pub fn read_hex_from_file_after_keyword(file: &mut File, keyword: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
pub fn read_message_from_file(file: &mut File) -> Option<String> {
    let reader = io::BufReader::new(file);
    for line in reader.lines() {
        if let Ok(line) = line {
            if let Some(start_index) = line.find("MESSAGE: '") {
                let start_index = start_index + "MESSAGE: '".len();
                if let Some(end_index) = line[start_index..].find("'") {
                    let message = line[start_index..start_index + end_index].to_string();
                    return Some(message);
                }
            }
        }
    }
    None
}
  
}
    