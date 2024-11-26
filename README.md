A small project to demonstrate the use of digital signatures.

The project makes use of
[`aws_lc_rs`](https://docs.rs/aws-lc-rs/latest/aws_lc_rs/signature/index.html) (an AWS maintained
cryptographic library implementation) to sign and verify a message.

- Try running the project via `cargo run`.
- Notice how the `VALID_MESSAGE` passes when verified against the signature.
- Notice how the `HACKED_MESSAGE` fails when verified against the same signature. Yes, we need to
  ensure that the attacker doesn’t also hack the valid signature.

