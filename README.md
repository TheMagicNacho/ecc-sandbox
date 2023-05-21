# Encryption Sandbox

Everything is in the main file, for right now.
I tried to make the code self documenting.


## Running the Sandbox
### Getting started
Install all the dependenceis: 
`cargo install --path .`

### Run it
`cargo run`

### How to lint before running the code
Since the complier is a little resource intenseive, try checking your code before running it:
`cargo check`


## How it's made
- We are creating asymetric keys using a hashed password.
- Currently using ECC ElGamal encryption.
- Since there is a limit to the size of the curve, we create a vector of scallars to hold the remainders of the message allong with the public keys.
- Everything is then serialized into binary for storage.
- After that, it is deserilized and decrypted.

