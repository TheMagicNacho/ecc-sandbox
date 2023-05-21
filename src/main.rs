
// Import all the required packages from kyber

use kyber_rs::group::edwards25519::SuiteEd25519;
use kyber_rs::util::random::RandStream;
use kyber_rs::group;
use kyber_rs::Point;
use kyber_rs::Scalar;
// use kyber_rs::Random;
use kyber_rs::Group;
// use std::str::from_utf8;
use sha3::{Digest, Sha3_256};
// use std::io;

use serde::{Serialize, Deserialize};

// RFI: How do we want to handle secrets? We could store secreets, so when the server dies we can recover the secrets OR secrets can die with the server. This would prevent people from accessing a dead drop if a node dies, but it increases the security of the data.
// NOTE: Implement kyber key exchange on the client
// TODO: Design end to end encryption using post quantum cryptography
// TODO: Make encrypt and decrypt apply to the Ticket Object
// TODO: Refactor into a factory
// TODO: Experiment with Postgres BLOB 

#[derive(Serialize, Deserialize, Debug)]
struct Ticket {
    encrypted_msg: Vec<group::edwards25519::Point>,
    ephemeral_keys: Vec<group::edwards25519::Point>,
}

fn main() {
  
    let m = "Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem. Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur?";
    
    let suite: SuiteEd25519 = SuiteEd25519::new_blake3_sha256_ed25519();

    // TICKET OBJECT
    // Generate a hash from a password to encrypt the message.
    let mut hasher = Sha3_256::new();
    hasher.update("password");
    let password_hash = hasher.finalize();

    // Generate Keys
    let private_key_a = suite.scalar().set_bytes(&password_hash); // Alice's private key
    let public_key_a = suite.point().mul(&private_key_a, None); // Alice's public key

    // ElGamal
    let mut remainder: Vec<u8> = m.as_bytes().to_vec();
    let mut encrypted_msg: Vec<group::edwards25519::Point> = Vec::new();
    let mut ephemeral_keys: Vec<group::edwards25519::Point> = Vec::new();
    
    while remainder.len() > 0 {
        let (ephmeral_key, cipher_text, remainder_temp) = el_gamal_encrypt(suite, &public_key_a, &remainder);
        remainder = remainder_temp;
     
        encrypted_msg.push(cipher_text);
        ephemeral_keys.push(ephmeral_key);
    }
    // println!("Encrypted Message: {:?}", encrypted_msg);
    let ticket = Ticket {
        encrypted_msg: encrypted_msg.clone(),
        ephemeral_keys: ephemeral_keys.clone(),
    };
    let ticket_binary = bincode::serialize(&ticket).unwrap();
    // print ticket_binary as a binary stream of bytes

    
    

    // DEAD DROP OBJECT
    // Generate a hash from a password to decrypt the message.
    let mut hash_puppy = Sha3_256::new();
    hash_puppy.update("password");
    let result2 = hash_puppy.finalize();
    // Deserialize the ticket
    let dead_drop: Ticket = bincode::deserialize(&ticket_binary).unwrap();


    let private_key2 = suite.scalar().set_bytes(&result2); // Alice's private key
    // Loop through the encrypted_msg vector, decrypting each message, concat to a string
    let mut decrypted_msg = Vec::new();
    for i in 0..encrypted_msg.len() {
        // println!("Encrypted Message: {:?}", encrypted_msg[i]);
        let dec_res: Result<Vec<u8>, group::PointError> = el_gamal_decrypt(suite, &private_key2, dead_drop.ephemeral_keys[i], dead_drop.encrypted_msg[i]);
        match dec_res {
            Ok(decrypted) => {
                for i in 0..decrypted.len() {
                    decrypted_msg.push(decrypted[i]);
                }
            },           
            Err(err) => println!("Decryption failed: {:?}", err),
        }
    }
    // println!("Decrypted Message: {:?}", String::from_utf8(decrypted_msg));

}

fn el_gamal_encrypt<GROUP: Group>(
    group: GROUP,
    pubkey: &GROUP::POINT,
    message: &[u8],
) -> (GROUP::POINT, GROUP::POINT, Vec<u8>) {
    // Embed the message (or as much of it as will fit) into a curve point.
    let m: <GROUP as Group>::POINT = group
        .point()
        .embed(Some(message), &mut RandStream::default());
    let mut max: usize = group.point().embed_len();
    if max > message.len() {
        max = message.len()
    }
    let remainder = message[max..].to_vec();
    // ElGamal-encrypt the point to produce ciphertext (K,C).
    let k = group.scalar().pick(&mut RandStream::default()); // ephemeral private key
    let k_p = group.point().mul(&k, None); // ephemeral DH public key
    let s = group.point().mul(&k, Some(pubkey)); // ephemeral DH shared secret
    let c = s.clone().add(&s, &m); // message blinded with secret
    (k_p, c, remainder)
}


pub fn el_gamal_decrypt<GROUP: Group>(
    group: GROUP,
    prikey: &<GROUP::POINT as Point>::SCALAR,
    ephemeral_key: GROUP::POINT,
    cipher_text: GROUP::POINT,
) -> Result<Vec<u8>, group::PointError> {
    // ElGamal-decrypt the ciphertext (K,C) to reproduce the message.
    let secret: <GROUP as Group>::POINT = group.point().mul(prikey, Some(&ephemeral_key)); // regenerate shared secret
    let point: <GROUP as Group>::POINT = group.point();
    let message: <GROUP as Group>::POINT = point.sub(&cipher_text, &secret); // use to un-blind the message
    return message.data();
}