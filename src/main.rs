
// Import all the required packages from kyber

use kyber_rs::group::edwards25519::SuiteEd25519;
use kyber_rs::util::random::RandStream;
use kyber_rs::group;
use kyber_rs::Point;
use kyber_rs::Scalar;
use kyber_rs::Group;
use sha3::{Digest, Sha3_256};

use serde::{Serialize, Deserialize};

// RFI: How do we want to handle secrets? We could store secreets, so when the server dies we can recover the secrets OR secrets can die with the server. This would prevent people from accessing a dead drop if a node dies, but it increases the security of the data.
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
  
    // This is the message that we want to encrypt in plaintext. 
    let m = "Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem. Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur?";
    

    // TICKET OBJECT
    // Generate a hash from a password to encrypt the message.
    let mut hasher_a = Sha3_256::new();
    hasher_a.update("password"); // password is provided by the user. you can change it to whatever you want.
    let password_hash_a = hasher_a.finalize();

    // Generate Keys
    let suite_a: SuiteEd25519 = SuiteEd25519::new_blake3_sha256_ed25519();
    let private_key_a = suite_a.scalar().set_bytes(&password_hash_a); // Alice's private key
    let public_key_a = suite_a.point().mul(&private_key_a, None); // Alice's public key

    // Instanciate Vectors to store the encryption types.
    let mut remainder: Vec<u8> = m.as_bytes().to_vec();
    let mut encrypted_msg: Vec<group::edwards25519::Point> = Vec::new();
    let mut ephemeral_keys: Vec<group::edwards25519::Point> = Vec::new();
    
    // Encrypt the message one block at a time, push both the ephemeral key and the cipher text to the respective vectors.
    while remainder.len() > 0 {
        let (ephmeral_key, cipher_text, remainder_temp) = encrypt(suite_a, &public_key_a, &remainder);
        remainder = remainder_temp;
    
        encrypted_msg.push(cipher_text);
        ephemeral_keys.push(ephmeral_key);
    }
    // println!("Encrypted Message: {:?}", encrypted_msg);
    let ticket = Ticket {
        encrypted_msg: encrypted_msg.clone(),
        ephemeral_keys: ephemeral_keys.clone(),
    };
    // Serialize the ticket for storage into the database.
    let ticket_binary = bincode::serialize(&ticket).unwrap();
    // println!("Ticket: {:?}", ticket_binary);

    
    

    // DEAD DROP OBJECT
    // Generate a hash from a password to decrypt the message.
    let mut hasher_b = Sha3_256::new();
    hasher_b.update("password"); // You can change this string to be whatever password you want. Try chaning the passwords so there is a mismatch.
    let password_hash_b = hasher_b.finalize();
    
    // Instanciate required objects and variables
    let dead_drop: Ticket = bincode::deserialize(&ticket_binary).unwrap(); // Deserialized from binary stream.
    let suite_b: SuiteEd25519 = SuiteEd25519::new_blake3_sha256_ed25519(); 
    let private_key2: group::edwards25519::Scalar = suite_b.scalar().set_bytes(&password_hash_b); // Generate decryption key
    let mut decrypted_msg: Vec<u8> = Vec::new();

    // Decrypt the message one block at a time, push the decrypted message to the decrypted_msg vector.
    for i in 0..encrypted_msg.len() {
        let dec_res: Result<Vec<u8>, group::PointError> = decrypt(suite_b, &private_key2, dead_drop.ephemeral_keys[i], dead_drop.encrypted_msg[i]);
        match dec_res {
            Ok(decrypted) => {
                for i in 0..decrypted.len() {
                    decrypted_msg.push(decrypted[i]);
                }
            },           
            Err(err) => println!("Decryption failed: {:?}", err),
        }
    }
    println!("Decrypted Message: {:?}", String::from_utf8(decrypted_msg));

}

fn encrypt<GROUP: Group>(
    group: GROUP,
    pubkey: &GROUP::POINT,
    message: &[u8],
) -> (GROUP::POINT, GROUP::POINT, Vec<u8>) {
    // Embed the message (or as much of it as will fit) into a curve point.
    let msg_slice: <GROUP as Group>::POINT = group
        .point()
        .embed(Some(message), &mut RandStream::default());
    let mut max: usize = group.point().embed_len();
    if max > message.len() {
        max = message.len()
    }
    let remainder = message[max..].to_vec();
    // ElGamal-encrypt the point to produce ciphertext (K,C).
    let ephemeral_private: <<GROUP as Group>::POINT as Point>::SCALAR = group.scalar().pick(&mut RandStream::default()); // ephemeral private key
    let ephemeral_public: <GROUP as Group>::POINT = group.point().mul(&ephemeral_private, None); // ephemeral DH public key
    let secret: <GROUP as Group>::POINT = group.point().mul(&ephemeral_private, Some(pubkey)); // ephemeral DH shared secret
    let cypher_text: <GROUP as Group>::POINT = secret.clone().add(&secret, &msg_slice); // message blinded with secret
    (ephemeral_public, cypher_text, remainder)
}


pub fn decrypt<GROUP: Group>(
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