use rand::{rngs::{ OsRng, StdRng}, Rng, SeedableRng};
use std::io;
use rand::distributions::uniform::SampleUniform;
use std::fmt::Debug;
use rand_chacha::{ChaCha20Rng};
use crate::enums::{RNG_Category, RustTypeSelect};

#[derive(Debug, PartialEq, Clone)]
pub enum RngType {
    Os,
    Std,
    ChaCha20,
}
#[derive(Debug, PartialEq, Clone)]
pub enum RngOutput<T> {
    Single(T),
    HexString(String),
    Vector(Vec<T>),
}

pub fn generate_random<T>(
    rng_type: RngType,
    range: (T, T),
) -> RngOutput<T>
where
    T: SampleUniform + Copy + PartialOrd + Debug + rand::distributions::uniform::SampleBorrow<T>,
{
    match rng_type {
        RngType::Os => {
            let mut rng = OsRng;
            let single_number = rng.gen_range(range.0..=range.1);
            RngOutput::Single(single_number)
        }
        RngType::Std => {
            let mut rng = StdRng::from_entropy();
            let single_number = rng.gen_range(range.0..=range.1);
            RngOutput::Single(single_number)
        }
        RngType::ChaCha20 => {
            let mut rng = ChaCha20Rng::from_entropy();
            let single_number = rng.gen_range(range.0..=range.1);
            RngOutput::Single(single_number)
        }
    }
}

pub fn generate_random_hex<T>(
    rng_type: RngType,
    length: usize,
) -> RngOutput<T>
where
    T: rand::distributions::uniform::SampleBorrow<u8> + Copy + Into<u8>,
{
    match rng_type {
        RngType::Os => {
            let mut rng = OsRng;
            let random_bytes: Vec<u8> = (0..length).map(|_| rng.gen_range(0..=255)).collect();
            let hex_string = hex::encode(random_bytes);
            RngOutput::HexString(hex_string)
        }
        RngType::Std => {
            let mut rng = StdRng::from_entropy();
            let random_bytes: Vec<u8> = (0..length).map(|_| rng.gen_range(0..=255)).collect();
            let hex_string = hex::encode(random_bytes);
            RngOutput::HexString(hex_string)
        }
        RngType::ChaCha20 => {
            let mut rng = ChaCha20Rng::from_entropy();
            let random_bytes: Vec<u8> = (0..length).map(|_| rng.gen_range(0..=255)).collect();
            let hex_string = hex::encode(random_bytes);
            RngOutput::HexString(hex_string)
        }
    }
}

pub fn generate_random_single<T>(
    rng_type: RngType,
    range: (T, T),
) -> RngOutput<T>
where
    T: SampleUniform + Copy + PartialOrd + Debug + rand::distributions::uniform::SampleBorrow<T>,
{
    match rng_type {
        RngType::Os => {
            let mut rng = OsRng;
            let single_number = rng.gen_range(range.0..range.1);
            RngOutput::Single(single_number)
        }
        RngType::Std => {
            let mut rng = StdRng::from_entropy();
            let single_number = rng.gen_range(range.0..range.1);
            RngOutput::Single(single_number)
        }
        RngType::ChaCha20 => {
            let mut rng = ChaCha20Rng::from_entropy();
            let single_number = rng.gen_range(range.0..range.1);
            RngOutput::Single(single_number)
        }
    }
}
pub fn generate_random_float(
    type_of: RNG_Category,
    rng_type: RngType,
    range: (f64, f64), 
    length:usize
) -> RngOutput<f64> 
where
    f64: rand::distributions::uniform::SampleUniform, 
{
    if type_of == RNG_Category::Single_number
    {
        let single_number = match rng_type {
            RngType::Os => {
                let mut rng = OsRng;
                rng.gen_range(range.0..range.1) 
            },
            RngType::Std => {
                let mut rng = StdRng::from_entropy();
                rng.gen_range(range.0..range.1)
            },
            RngType::ChaCha20 => {
                let mut rng = ChaCha20Rng::from_entropy();
                rng.gen_range(range.0..range.1)
            },
        };
        RngOutput::Single(single_number)
    }
    else {
        let mut vec_out:Vec<f64> = Vec::new(); 
        let mut x:f64 = 0.0;
        match rng_type {
            RngType::Os => {
                let mut rng = OsRng;
                for _ in 0..length {
                    let x = rng.gen_range(range.0..range.1);
                    vec_out.push(x);
                }
            }
            RngType::Std => {
                let mut rng = StdRng::from_entropy();
                for _ in 0..length {
                    let x = rng.gen_range(range.0..range.1);
                    vec_out.push(x);
                }
            }
            RngType::ChaCha20 => {
                let mut rng = ChaCha20Rng::from_entropy();
                for _ in 0..length {
                    let x = rng.gen_range(range.0..range.1);
                    vec_out.push(x);
                }
            }
        };
          
        return RngOutput::Vector(vec_out);
    }

}

pub fn generate_random_vector<T>(
    rng_type: RngType,
    range: (T, T),
    length: usize,
) -> RngOutput<T>
where
    T: SampleUniform + Copy + PartialOrd + Debug + rand::distributions::uniform::SampleBorrow<T>,
{
    let random_values: Vec<T> = match rng_type {
        RngType::Os => {
            let mut rng = OsRng;
            (0..length)
                .map(|_| rng.gen_range(range.0..=range.1))
                .collect()
        },
        RngType::Std => {
            let mut rng = StdRng::from_entropy();
            (0..length)
                .map(|_| rng.gen_range(range.0..=range.1))
                .collect()
        },
        RngType::ChaCha20 => {
            let mut rng = ChaCha20Rng::from_entropy();
            (0..length)
                .map(|_| rng.gen_range(range.0..=range.1))
                .collect()
        },
    };

    RngOutput::Vector(random_values)
}
pub fn get_input_within_bounds(rust_type: &RustTypeSelect) -> Option<(i128, i128)> {
    let bounds = get_bounds_for_type(rust_type);
    match bounds {
        Some((lower_bound, upper_bound)) => {
            loop {
               if rust_type != &RustTypeSelect::u128
               {
                println!("Do you want to set bounds for the random number generation?\nCurrently cannot set bounds above i128\nYour selected type infimum and supremum({}, {})\nWould you like to set bounds? (y)es/(n)o)", lower_bound, upper_bound);
               }
               else
               {
                println!("Do you want to set bounds for the random number generation?\nCurrently cannot set bounds above i128\nYour selected type infimum and supremum({}, {})\nWould you like to set bounds?  (y)es/(n)o)", std::u128::MIN, std::u128::MAX);
               }
                let mut input = String::new();
                io::stdin().read_line(&mut input).expect("Failed to read line");
                let response = input.trim().to_lowercase();
                if response.contains("y") {
                    println!("Enter lower bound, press return then similarly for the upper bound:");
                    let mut lower_input = String::new();
                    io::stdin().read_line(&mut lower_input).expect("Failed to read line");
                    let mut upper_input = String::new();
                    io::stdin().read_line(&mut upper_input).expect("Failed to read line");
                    match (lower_input.trim().parse(), upper_input.trim().parse()) {
                        (Ok(lower), Ok(upper)) => {
                            return Some((lower, upper));
                        },
                        _ => println!("Please enter valid lower and upper bounds."),
                    }
                }
                 else if response.contains("n") 
                {
                   return None
                } 
                else {
                    println!("Please enter either 'yes' or 'no'.");
                }
            }
        },
        None => {
            println!("Cannot currently set bounds for floats.");
            return None;
            }
        }
    }



pub fn get_length(min: usize, max: usize) -> usize {
    loop {
        println!("Enter the length of the random output ({} to {}):", min, max);
        let mut input = String::new();
        io::stdin().read_line(&mut input)
            .expect("Failed to read line");
        match input.trim().parse() {
            Ok(length) if length >= min && length <= max => return length,
            Ok(_) => println!("Please enter a number between {} and {}.", min, max),
            Err(_) => println!("Please enter a valid number."),
        }
    }
}

pub fn get_bounds_for_type(rust_type: &RustTypeSelect) -> Option<(i128, i128)> {
    match rust_type {
        RustTypeSelect::u8 => Some((0, std::u8::MAX as i128)),
        RustTypeSelect::i8 => Some((std::i8::MIN as i128, std::i8::MAX as i128)),
        RustTypeSelect::u16 => Some((0, std::u16::MAX as i128)),
        RustTypeSelect::i16 => Some((std::i16::MIN as i128, std::i16::MAX as i128)),
        RustTypeSelect::u32 => Some((0, std::u32::MAX as i128)),
        RustTypeSelect::i32 => Some((std::i32::MIN as i128, std::i32::MAX as i128)),
        RustTypeSelect::u64 => Some((0, std::u64::MAX as i128)),
        RustTypeSelect::i64 => Some((std::i64::MIN as i128, std::i64::MAX as i128)),
        RustTypeSelect::u128 => Some((0, 0)),
        RustTypeSelect::i128 => Some((std::i128::MIN, std::i128::MAX)),
        RustTypeSelect::f32  => None, 
    }
}


pub fn select_rng_type() -> Result<RngType, &'static str> {
    println!("Select RNG type:");
    println!("1. Os");
    println!("2. Std");
    println!("3. ChaCha20");

    loop {
        println!("Enter the number corresponding to your choice:");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read input");
        let choice: u32 = match input.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                println!("Please enter a valid number.");
                continue;
            }
        };

        match choice {
            1 => return Ok(RngType::Os),
            2 => return Ok(RngType::Std),
            3 => return Ok(RngType::ChaCha20),
            _ => println!("Invalid choice. Please select a number from 1 to 3."),
        }
    }
}


pub fn select_rust_type() -> Result<RustTypeSelect, ()> {
    println!("Select Rust type for T:");
    println!("1. u8");
    println!("2. i8");
    println!("3. u16");
    println!("4. i16");
    println!("5. u32");
    println!("6. i32");
    println!("7. u64");
    println!("8. i64");
    println!("9. u128");
    println!("10. i128");
    println!("11. f32");

    loop {
        println!("Enter the number corresponding to your choice:");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read input");
        let choice: u32 = match input.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                println!("Please enter a valid number.");
                continue;
            }
        };

        match choice {
            1 => return Ok(RustTypeSelect::u8),
            2 => return Ok(RustTypeSelect::i8),
            3 => return Ok(RustTypeSelect::u16),
            4 => return Ok(RustTypeSelect::i16),
            5 => return Ok(RustTypeSelect::u32),
            6 => return Ok(RustTypeSelect::i32),
            7 => return Ok(RustTypeSelect::u64),
            8 => return Ok(RustTypeSelect::i64),
            9 => return Ok(RustTypeSelect::u128),
            10 => return Ok(RustTypeSelect::i128),
            11 => return Ok(RustTypeSelect::f32),
            _ => println!("Invalid choice. Please select a number from 1 to 11."),
        }
    }
}
