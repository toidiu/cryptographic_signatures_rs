use aws_lc_rs::{
    error::Unspecified,
    pkcs8::Document,
    rand::SystemRandom,
    signature::{self, Ed25519KeyPair, KeyPair, Signature, UnparsedPublicKey},
};

// This code modifies an example from aws-lc documentation.
//
// https://docs.rs/aws-lc-rs/latest/aws_lc_rs/signature/index.html#signing-and-verifying-with-ed25519

const VALID_MESSAGE: &[u8] = b"Transfer $100 to Bob.";
// Hacker is trying to transer $1000
const HACKED_MESSAGE: &[u8] = b"Transfer $1000 to Bob.";
// Bob is now Amy
const HACKED_MESSAGE_1: &[u8] = b"Transfer $100 to Amy.";
// Bob is missing a 'b'
const PACKET_LOSS_MESSAGE: &[u8] = b"Transfer $100 to Bo.";
// extra space between to and Bob
const MISTAKE_MESSAGE: &[u8] = b"Transfer $1000 to  Bob.";

fn main() -> Result<(), Unspecified> {
    let key_pair: Ed25519KeyPair = generate_key_pair_for_signature();

    // The Application signs a VALID_MESSAGE.
    let signature_for_valid_message: Signature = key_pair.sign(VALID_MESSAGE);

    // The Bank
    {
        // Get the public key key directly from the key pair.
        //
        // Normally an application would extract the bytes of the signature and send them in a protocol
        // (TLS) message to the peer(s).
        let peer_public_key: UnparsedPublicKey<&[u8]> =
            UnparsedPublicKey::new(&signature::ED25519, key_pair.public_key().as_ref());

        // Verify the signature of the VALID_MESSAGE using the public key.
        //
        // Normally the verifier of the message would parse the inputs to this code out of the
        // protocol message(s) sent by the signer.
        let verification_result: Result<(), Unspecified> = peer_public_key
            .verify(VALID_MESSAGE, signature_for_valid_message.as_ref());
        // Verify PASSES for VALID_MESSAGE
        assert!(verification_result.is_ok());

        let verification_result: Result<(), Unspecified> =
            peer_public_key.verify(HACKED_MESSAGE, signature_for_valid_message.as_ref());
        // Verify FAILS for HACKED_MESSAGE!!
        assert!(verification_result.is_err());

        let verification_result: Result<(), Unspecified> =
            peer_public_key.verify(HACKED_MESSAGE_1, signature_for_valid_message.as_ref());
        // Verify FAILS for HACKED_MESSAGE_1!!
        assert!(verification_result.is_err());

        let verification_result: Result<(), Unspecified> =
            peer_public_key.verify(PACKET_LOSS_MESSAGE, signature_for_valid_message.as_ref());
        // Verify FAILS for PACKET_LOSS_MESSAGE!!
        assert!(verification_result.is_err());

        let verification_result: Result<(), Unspecified> =
            peer_public_key.verify(MISTAKE_MESSAGE, signature_for_valid_message.as_ref());
        // Verify FAILS for MISTAKE_MESSAGE!!
        assert!(verification_result.is_err());
    }

    Ok(())
}

fn generate_key_pair_for_signature() -> Ed25519KeyPair {
    // Generate a key pair in PKCS#8 format.
    let rng: SystemRandom = SystemRandom::new();
    let pkcs8_bytes: Document = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

    // Normally the application would store the PKCS#8 file persistently. Later
    // it would read the PKCS#8 file from persistent storage to use it.
    Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap()
}
