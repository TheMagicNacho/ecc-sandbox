// use kyber_rs::util::random::RandStream;
// use kyber_rs::group::edwards25519::SuiteEd25519;
// use kyber_rs::Point;
// use kyber_rs::Group;
// use kyber_rs::Random;
// use kyber_rs::group::Scalar;



// // use anyhow::Result;

// pub struct Ticket<G>
//     {
//         title: String,
//     payload: String,
//     ephemeral_key: GROUP,
//   }
  
//   impl<GROUP> Ticket<GROUP> {
//     pub fn new(title: String, payload: String) -> Ticket<Group> {

//         let suite = SuiteEd25519::new_blake3_sha256_ed25519();
//         // Create a public/private keypair
//         let private_key = suite.scalar().pick(&mut suite.random_stream()); // Alice's private key
//         let public_key = suite.point().mul(&private_key, None); // Alice's public key
//         // ElGamal-encrypt a message using the public key.
//         let plaintext = payload.as_bytes();
//         let (ephemeral_key, cypher_text, remainder) = Ticket::encrypt(suite, &public_key, plaintext);
//         println!("key: {:?}", ephemeral_key);
//         println!("encrypted messege: {:?}", cypher_text);
//         println!("remainder: {:?}", remainder);
//         // let payload = cypher_text.to_string();
//      Ticket {
//        title,
//        payload,
//        ephemeral_key,
//      } 
//     }
  
//     pub fn show_ticket(&self) {
//       println!("Title: {}", self.title);
//       println!("Messege: {}", self.payload);
//     }
  
    
//     pub fn encrypt<GROUP: Group>(
//         group: GROUP,
//         pubkey: &GROUP::POINT,
//         message: &[u8],
//     ) -> (GROUP::POINT, GROUP::POINT, Vec<u8>) {
//         // Embed the message (or as much of it as will fit) into a curve point.
//         let m = group
//             .point()
//             .embed(Some(message), &mut RandStream::default());
//         let mut max = group.point().embed_len();
//         if max > message.len() {
//             max = message.len()
//         }
//         let remainder = message[max..].to_vec();
//         // ElGamal-encrypt the point to produce ciphertext (K,C).
//         let k = group.scalar().pick(&mut RandStream::default()); // ephemeral private key
//         let k_p = group.point().mul(&k, None); // ephemeral DH public key
//         let s = group.point().mul(&k, Some(pubkey)); // ephemeral DH shared secret
//         let c = s.clone().add(&s, &m); // message blinded with secret
//         (k_p, c, remainder)
//     }

// //     pub fn read (self) -> String {
// //         self.payload
// //     }

// //     pub fn decrypt<GROUP: Group> (
// //     // suite: GROUP,
// //     prikey: &<GROUP::POINT as Point>::SCALAR,
// //     k: GROUP::POINT,
// //     c: GROUP::POINT,
// // ) -> Result<Vec<u8>> {



// //     let suite = SuiteEd25519::new_blake3_sha256_ed25519();


// //     // ElGamal-decrypt the ciphertext (K,C) to reproduce the message.
// //     let s = suite.point().mul(prikey, Some(&k)); // regenerate shared secret
// //     let p = suite.point();
// //     let m = p.sub(&c, &s); // use to un-blind the message
// //     Ok(m.data()?)
// // }
  
    
    
//   }