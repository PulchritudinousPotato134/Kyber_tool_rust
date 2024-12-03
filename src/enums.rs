
// Define categories
#[derive(Debug, PartialEq, Clone)]
pub enum Category {
    AES,
    Dilithium,
    Kyber,
    Primality,
    Hashing,
    SecureKey,
    TLS,
    Email,
    RNG,
    ZNP,
    SFD,
    SS,
    Extra,
    Export,
    CUA,
    MD,
    Docs,
    
}
#[derive(Debug, PartialEq, Clone)]
pub enum AES_Category {
    ECB,
    CTR,
    OFB,
    GCM,
    GCM_SIV,
    CBC,
    CCM,
    Exit
    
}
#[derive(Debug, PartialEq, Clone)]
pub enum AES_Strength_Category {
    AES128,
    AES192,
    AES256
}
#[derive(Debug, PartialEq, Clone)]
pub enum Dilithium_Category {
    Dilithium2,
    Dilithium3,
    Dilithium5,
    Exit
   
}
#[derive(Debug, PartialEq, Clone)]
pub enum Kyber_Category {

    Kyber512,
    Kyber768,
    Kyber1024,
    Exit
   
}
#[derive(Debug, PartialEq, Clone)]
pub enum Primality_Category {
    Erastothenes,
    Solovay,
    Miller,
    GenPrimeOfBits,
    RingResidue,
    Euclidean,
    ExtendedEuclidean,
    EulerTotient,
    PrimeCounting,
    ModPower,
    QuadraticResidue,
    ExponentialResidue,
    GenerateEmirps,
    GenerateCousinPrimes,
    GenerateSexyPrimes,
    IsSafePrime,
    IsPalindromePrime,
    IsTwinPrime,
    PollardsRho,
    ListSophie,
    ListSafePrimes,
    ListPallindromePrimes,
    ListTwinPrimes,
    IsSexyPrime,
    IsCousinPrime,
    IsEmirp,
    KFreeTest,
    Legendre,
    Jacobi,
    Kronecker,
    GenPrimeLess,
    GenNth,
    GenRange,
    GenPrimeFactors,
    IsPrime,
    GCD,
    LCM,
    Coprime,
    ListMersenne,
    IsMersenne,
    FermatPrime,
    IsSophie,
    LucasProbablePrime,
    StrongLucasProbablePrime,
    ExtraStrongLucasProbablePrime,
    Exit

}
#[derive(Debug, PartialEq, Clone)]
pub enum RustTypeSelect
{
    u8,
    i8,
    u16,
    i16,
    u32,
    i32,
    u64,
    i64,
    u128,
    i128,
    f32,
}
#[derive(Debug, PartialEq, Clone)]
pub enum Hashing_Category {
    Shake128,
    Shake256,
    Sha2_224,
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Sha2_512_224,
    Sha2_512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Keccak224,
    Keccak256,
    Keccak384,
    Keccak512,
    Exit
}
#[derive(Debug, PartialEq, Clone)]
pub enum SecureKey_Category {
   OsRng,
   Pbkdf2,
   Combo,
   Exit
}
#[derive(Debug, PartialEq, Clone)]
pub enum TLS_Category {
  Server,
  Client,
  Exit
}
#[derive(Debug, PartialEq, Clone)]
pub enum Email_Category {
   Generate_PGP,
   Store_PGP,
   Send_Email,
   Load_PGP,
   Exit
}
#[derive(Debug, PartialEq, Clone)]
pub enum RNG_Category {
    Single_number,
    Hex,
    Vector,
    Exit
}
#[derive(Debug, PartialEq, Clone)]
pub enum ZNP_Category {
   Schnorr,
   Exit
}
#[derive(Debug, PartialEq, Clone)]
pub enum Erasure_Category {
    Gutmann,
    DoD5220_22M,
    NIST800_88,
    Exit
}
#[derive(Debug, PartialEq, Clone)]
pub enum SecureStorageCategory {
   CreateSection,
   UploadKey,
   RetrieveKey,
   DeleteKey,
   Exit
}
#[derive(Debug, PartialEq, Clone)]
pub enum Extra_Category {
 
    
}
#[derive(Debug, PartialEq, Clone)]
pub enum Export_Category {
    Binary,
    Hexadecimal,
    Base64,
    JSON,
    Protobuf,
    PEM,
    Exit
}
#[derive(Debug, PartialEq, Clone)]
pub enum User_Category {
    CreateAccount,
    ChangePassword,
    ChangeEmail,
    DeleteUser,
    Exit
    
}
#[derive(Debug, PartialEq, Clone)]
pub enum MD_Category {

    
}
#[derive(Debug, PartialEq, Clone)]
pub enum Docs_Category {
    AES,
    Dilithium,
    Kyber,
    Primality,
    Hashing,
    SecureKey,
    TLS,
    Email,
    RNG,
    ZNP,
    SFD,
    SS,
    Extra,
    Export,
    CUA,
    MD,
    Docs,
    Exit
}

#[derive(Debug, PartialEq, Clone)]
pub enum KeyStorage {
    AESECB,
    AESOFB,
    AESCBC,
    AESCTR,
    AESGCM,
    AESGCMSIV,
    AESCCM,
    Kyber2Public,
    Kyber2Private,
    Kyber2SharedSecret,
    Kyber3Public,
    Kyber3Private,
    Kyber3SharedSecret,
    Kyber4Public,
    Kyber4Private,
    Kyber4SharedSecret,
    Dilithium2Public,
    Dilithium2Private,
    Dilithium2SignedMessages,
    Dilithium3Public,
    Dilithium3Private,
    Dilithium3SignedMessages,
    Dilithium4Public,
    Dilithium4Private,
    Dilithium4SignedMessages,
    EmailPGPKeys
}