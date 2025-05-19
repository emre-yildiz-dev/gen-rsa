use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePrivateKey, EncodePublicKey}};
use rand::thread_rng;
use std::fs::File;
use std::io::Write;
use base64::{engine::general_purpose, Engine as _};


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();
    let bits = 4096;

    // Generate RSA key pair
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);

    // ========== Step 1: Save PEM Files ==========
    let private_pem = private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?;

    let mut priv_pem_file = File::create("private_key.pem")?;
    priv_pem_file.write_all(private_pem.as_bytes())?;

    let public_pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;
    let mut pub_pem_file = File::create("public_key.pem")?;
    pub_pem_file.write_all(public_pem.as_bytes())?;

    // ========== Step 2: Encode to Base64 ==========

    let private_b64 = general_purpose::STANDARD.encode(private_pem.as_bytes());
    let public_b64 = general_purpose::STANDARD.encode(public_pem.as_bytes());

    let mut priv_b64_file = File::create("private_key.b64")?;
    priv_b64_file.write_all(private_b64.as_bytes())?;

    let mut pub_b64_file = File::create("public_key.b64")?;
    pub_b64_file.write_all(public_b64.as_bytes())?;

    println!("✅ RSA PEM and Base64 files created successfully.");

    Ok(())
}
