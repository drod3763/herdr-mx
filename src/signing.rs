//! Release-artifact authenticity: verify minisign (ed25519) detached signatures against a
//! public key embedded in the binary.
//!
//! This is the authenticity leg of the bundle / remote-seed / update integrity chain. SHA-256
//! (see [`crate::checksum`]) catches corruption and at-rest tampering, but a signature is the only
//! thing that survives a compromised release host: an attacker without the private key cannot forge
//! one. herdr-mx auto-executes downloaded binaries on remote hosts, so seed/update flows verify a
//! signature before any binary is run or installed.

use std::io;
use std::path::Path;

use minisign_verify::{PublicKey, Signature};

/// Minisign public key(s) accepted for release-artifact verification, as the base64 key line
/// (the `RW…` string, second line of a minisign `.pub`).
///
/// An array so a key can be rotated without a flag day: a signature from ANY listed key is
/// accepted, so a new key ships in one release while the old key still verifies prior assets;
/// the old key is dropped a release later.
///
/// The private half lives only in the `MINISIGN_SECRET_KEY` GitHub Actions secret; CI signs every
/// release asset and fat bundle into a `<asset>.minisig` sidecar. To rotate, prepend the new key
/// here, ship a release, then drop the old key a release later.
const ACCEPTED_PUBKEYS: &[&str] = &[
    // herdr-mx release signing key 31670D1E13849B12
    "RWQupm2xx/vDQ2YjRHgy/84xAkdgzIgwIN/4CyOy5n1rQRQnHW34r3D2",
];

/// Verify a detached minisign signature over the contents of `file`.
///
/// `signature` is the raw bytes of the `.minisig` file (comment lines + base64), exactly as
/// downloaded alongside the asset.
pub(crate) fn verify_signature(file: &Path, signature: &[u8]) -> io::Result<()> {
    let data = std::fs::read(file)?;
    verify_signature_bytes(&data, signature)
}

/// Verify a detached minisign signature over `data` against the embedded release keys.
pub(crate) fn verify_signature_bytes(data: &[u8], signature: &[u8]) -> io::Result<()> {
    verify_with_keys(data, signature, ACCEPTED_PUBKEYS)
}

/// Core verifier, parameterized over the accepted keys so tests can supply their own keypair
/// without touching the production [`ACCEPTED_PUBKEYS`].
fn verify_with_keys(data: &[u8], signature: &[u8], pubkeys: &[&str]) -> io::Result<()> {
    if pubkeys.is_empty() {
        return Err(io::Error::other(
            "no release signing keys are configured; cannot verify artifact authenticity",
        ));
    }

    let signature_text = std::str::from_utf8(signature).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "minisign signature is not valid UTF-8",
        )
    })?;
    let signature = Signature::decode(signature_text).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid minisign signature: {err}"),
        )
    })?;

    let mut last_error: Option<String> = None;
    for encoded in pubkeys {
        let public_key = match PublicKey::from_base64(encoded) {
            Ok(public_key) => public_key,
            Err(err) => {
                last_error = Some(format!("invalid embedded public key: {err}"));
                continue;
            }
        };
        match public_key.verify(data, &signature, false) {
            Ok(()) => return Ok(()),
            Err(err) => last_error = Some(format!("signature verification failed: {err}")),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        last_error.unwrap_or_else(|| "signature verification failed".to_string()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only keypair (empty password), generated with `minisign -G -W`. NOT a release key.
    const TEST_PUBKEY: &str = "RWQS9/1J0f5eBSLoA3e8U4hbWems0Lakm+xJ0AOBBzGpUvXTe7VWkRSC";
    const TEST_PAYLOAD: &[u8] = b"herdr-mx signing test payload\n";
    const TEST_SIGNATURE: &str = "untrusted comment: signature from minisign secret key\n\
RUQS9/1J0f5eBePEEKP3AnL4xV/YO7xJuoLXbfYl1CWSJb2lZVWAIEnXAGcS6wDXoBf9Z/wpd837bi8G3FcFh/5FCy9o1Sp0Rg8=\n\
trusted comment: timestamp:1782408946\tfile:payload.bin\thashed\n\
f/eZIK9QFwcdBVJC+bN/QWbdQQbv2C11XYExgJ/7VHh0tW24B9kXt0kwHLR/JCrfEct7y9Z0Otwl/GPdZUUTDg==\n";

    #[test]
    fn verifies_good_signature() {
        verify_with_keys(TEST_PAYLOAD, TEST_SIGNATURE.as_bytes(), &[TEST_PUBKEY])
            .expect("valid signature must verify");
    }

    #[test]
    fn rejects_tampered_payload() {
        let mut tampered = TEST_PAYLOAD.to_vec();
        tampered[0] ^= 0x01;
        let err = verify_with_keys(&tampered, TEST_SIGNATURE.as_bytes(), &[TEST_PUBKEY])
            .expect_err("tampered payload must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_wrong_key() {
        // A different valid minisign public key — correct format, wrong identity.
        const OTHER_PUBKEY: &str = "RWTgr3uPbVfDfFw5N8z4o6lQ8e8nN0q0a8m9s8KQ0+test+key+notreal=";
        let err = verify_with_keys(TEST_PAYLOAD, TEST_SIGNATURE.as_bytes(), &[OTHER_PUBKEY])
            .expect_err("wrong key must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn fails_closed_with_no_keys() {
        let err = verify_with_keys(TEST_PAYLOAD, TEST_SIGNATURE.as_bytes(), &[])
            .expect_err("no configured keys must fail closed");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn production_keys_are_configured_and_well_formed() {
        // Verification fails closed with no keys, so a release key must always be present and
        // decodable. If this fires, CI signing and the embedded key are out of sync.
        assert!(
            !ACCEPTED_PUBKEYS.is_empty(),
            "a release signing key is required"
        );
        for encoded in ACCEPTED_PUBKEYS {
            PublicKey::from_base64(encoded).expect("embedded release public key must decode");
        }
    }
}
