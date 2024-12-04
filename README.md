This is version of Kyber I converted into Rust from the C reference implementation. It is quite simple and does the encapsulation and decapsulation for all 3 security strengths. It has been extarcted from a larger project I completed so there will be little bits of extra code that don't appear to be used.
Please feel free to use and update it. It would be nice if you referenced this if you do use it. 

Please note that many terminals have input restrictions on length. As such for decapsulation mode please supply keys in a separate file. The format is demonstrated below:
Order does not matter, for decapsulation only private key and ciphertext are required. If you would like to validate the shared secret, include it in the file and the program will alert to a match.
This is also the format that the program will output in encapsulation mode.

PRIVATE KEY: <HEX VALUE>
PUBLIC KEY: <HEX VALUE>
Ciphertext: <HEX VALUE>
Shared Secret: <HEX VALUE>

Encapsulation mode does not require any input. However, you can supply your own key if you wish.
Your output will be saved in the keyfile provided.

Usage: my_program [options]
Options:
--help, -h Show this help message
--sec,                       -s   Security level selection: 2, 3, or 5  
  --enc,                       -e   Encapsulation mode  
  --key-file <file path>,      -f   Use keyfile  
  --own-key                    -o   Use own public key  

Example use for using own key:  
./kyber --sec 5 --enc --key-file /home/my_output/kyber_output --own-key  
Alternatively:  
./kyber -s 5 -e -f /home/my_output/kyber_output -o  

QUICK USE  
You can use the following style of command to quickly run encapsulation with default settings.  
./kyber -E<security_level> /home/file_for_key  
e.g. ./kyber -E5 /home/my_encapsulation  

Example input to use key generation:  
./kyber --sec 3 --enc --key-file /home/my_output/kyber_output  
Alternatively:  
./kyber -s 3 -e -f /home/my_output/kyber_output  

~~~For Decapsulation Mode~~~  
  --sec,                       -s   Security level selection: 2, 3, or 5  
  --dec,                       -d   Decapsulation mode  
  --key-file <file path>,      -f   Use keyfile  

Example input to decapsulate:  
./kyber --sec 3 --dec --key-file /home/my_output/kyber_output  
Alternatively:  
./kyber -s 3 -d -f /home/my_output/kyber_output  

QUICK USE  
You can use the following style of command to quickly run decapsulation with default settings.  
./kyber -D<security_level> /home/file_for_key  
e.g. ./kyber -D5 /home/my_decapsulation  

Options for security level:  
  2                             Kyber 512  
  3                             Kyber 768  
  5                             Kyber 1024  

--- 
