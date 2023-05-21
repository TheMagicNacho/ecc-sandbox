use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce // Or `Aes128Gcm`
};


fn main() {

    let key = Aes256Gcm::generate_key(&mut OsRng);
    
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message

    println!("Test");
    let ciphertext: Vec<u8> = match cipher.encrypt(nonce, "plaintext message".as_bytes()) {
        Ok(ciphertext) => ciphertext,
        Err(err) => panic!("Failed to encrypt: {:?}", err)
    };
    println!("{:?}", ciphertext);


    let plaintext: Vec<u8> = match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(plaintext) => plaintext,
        Err(err) => panic!("Failed to decrypt: {:?}", err)
    };
    println!("{:?}", String::from_utf8_lossy(&plaintext));
}