
use rand::Rng;

use crate::kyber::helping_functions;

use super::kem;


#[derive(Debug,Clone)]
pub struct KyberParams {
    pub kyber_k: u32,
    pub kyber_namespace: String,
    pub kyber_n: u32,
    pub kyber_q: u32,
    pub kyber_symbytes: u32,
    pub kyber_ssbytes: u32,
    pub kyber_polybytes: u32,
    pub kyber_polycompressedbytes: u32,
    pub kyber_polyvecbytes: u32,
    pub kyber_eta1: u32,
    pub kyber_polyveccompressedbytes: u32,
    pub kyber_eta2: u32,
    pub kyber_indcpa_msgbytes: u32,
    pub kyber_indcpa_publickeybytes: u32,
    pub kyber_indcpa_secretkeybytes: u32,
    pub kyber_indcpa_bytes: u32,
    pub kyber_publickeybytes: u32,
    pub kyber_secretkeybytes: u32,
    pub kyber_ciphertextbytes: u32,
}

impl KyberParams {
    pub fn set_parameters(security_level: u32) -> Option<KyberParams> {
        match security_level {
            2 => Some(KyberParams {
                kyber_k: 2,
                kyber_namespace: "pqcrystals_kyber512_ref".to_string(),
                kyber_n: 256,//
                kyber_q: 3329,//
                kyber_symbytes: 32,//
                kyber_ssbytes: 32,//
                kyber_polybytes: 384,//
                kyber_polycompressedbytes: 128,
                kyber_eta1: 3,
                kyber_polyveccompressedbytes: 640,
                kyber_polyvecbytes: 768,
                kyber_eta2: 2,
                kyber_indcpa_msgbytes: 32,
                kyber_indcpa_publickeybytes: 800,
                kyber_indcpa_secretkeybytes: 768,
                kyber_indcpa_bytes: 768,
                kyber_publickeybytes: 800,
                kyber_secretkeybytes: 1632,
                kyber_ciphertextbytes: 768,
            }),
            3 => Some(KyberParams {
                kyber_k: 3,
                kyber_namespace: "pqcrystals_kyber768_ref".to_string(),
                kyber_n: 256,//
                kyber_q: 3329,//
                kyber_symbytes: 32,//
                kyber_ssbytes: 32,//
                kyber_polybytes: 384,//
                kyber_polycompressedbytes: 128,
                kyber_eta1: 2,
                kyber_polyveccompressedbytes: 960,
                kyber_polyvecbytes: 1152,
                kyber_eta2: 2,
                kyber_indcpa_msgbytes: 32,
                kyber_indcpa_publickeybytes: 1184,
                kyber_indcpa_secretkeybytes: 1152,
                kyber_publickeybytes: 1184,
                kyber_secretkeybytes: 2400,
                kyber_indcpa_bytes: 1088,
                kyber_ciphertextbytes: 1088,
            }),
            4 => Some(KyberParams {
                kyber_k: 4,
                kyber_namespace: "pqcrystals_kyber1024_ref".to_string(),
                kyber_n: 256,//
                kyber_q: 3329,//
                kyber_symbytes: 32,//
                kyber_ssbytes: 32,//
                kyber_polybytes: 384,//
                kyber_polycompressedbytes: 160,
                kyber_eta1: 2,
                kyber_polyvecbytes: 1536,
                kyber_polyveccompressedbytes: 1408,
                kyber_eta2: 2,
                kyber_indcpa_msgbytes: 32,
                kyber_indcpa_publickeybytes: 1568,
                kyber_indcpa_secretkeybytes: 1536,
                kyber_indcpa_bytes: 1568,
                kyber_publickeybytes: 1568,
                kyber_secretkeybytes: 3168,
                kyber_ciphertextbytes: 1568,
            }),
            _ => None, // Handle other security levels or return an error
        }
    }
}
#[derive(Debug,Clone)]
pub struct Kyber {
    pub params: KyberParams, 
    has_key_been_generated: bool,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    private_key_password: String,
}

impl Kyber {
        pub fn create(security_level: u32) -> Kyber 
        {
            let params = KyberParams::set_parameters(security_level).expect("Invalid security level");
    
            let mut kyber_instance = Kyber {
                params: params.clone(), // Assuming KyberParams implements Clone
                has_key_been_generated: false,
                public_key: Vec::new(),
                private_key: Vec::new(),
                private_key_password: String::new(),
            };
    
            kyber_instance
        }

}
