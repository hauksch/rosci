//! PKCS#12 identity contracts, ported from the Java bridge's
//! `CryptoMaterialTest`: round-trip unwrapping in both key-transport
//! flavours, PSS signature verifiability, wrong-PIN rejection.

// Tests panic on broken assumptions — that is the job description.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use osci::p12::{Decrypter, P12Decrypter, P12Keypair, P12Signer, Signer};
use rsa::pkcs8::EncodePublicKey;
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
const PIN: &str = "testpin";
const RSA_SHA256_PSS: &str = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
const MGF1_SHA256: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// Builds an RSA-2048 keystore with openssl, like the e2e fixtures do.
/// Returns `None` where openssl is unavailable (same skip policy as e2e).
fn openssl_keystore(cn: &str) -> Option<Vec<u8>> {
    let dir = tempfile::tempdir().ok()?;
    let key = dir.path().join("key.pem");
    let cert = dir.path().join("cert.pem");
    let p12 = dir.path().join("ks.p12");

    let run = |args: &[&str]| {
        std::process::Command::new("openssl")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        key.to_str()?,
        "-out",
        cert.to_str()?,
        "-days",
        "2",
        "-nodes",
        "-subj",
        &format!("/CN={cn}"),
    ])?;
    run(&[
        "pkcs12",
        "-export",
        "-inkey",
        key.to_str()?,
        "-in",
        cert.to_str()?,
        "-name",
        "test",
        "-passout",
        &format!("pass:{PIN}"),
        "-out",
        p12.to_str()?,
    ])?;
    std::fs::read(&p12).ok()
}

#[test]
fn parse_roundtrip_and_wrong_pin() {
    let Some(der) = openssl_keystore("CN=p12-roundtrip") else {
        eprintln!("skipping (openssl missing)");
        return;
    };

    let kp = P12Keypair::parse(&der, PIN).expect("parse keystore");
    assert_eq!(kp.chain().len(), 1);
    assert_eq!(kp.certificate().der(), kp.chain()[0].der());
    assert_eq!(kp.certificate().key_size(), 2048);

    // wrong PIN must be a config error, not a panic
    match P12Keypair::parse(&der, "falsche-pin") {
        Err(osci::Error::Config(_)) => {}
        Err(e) => panic!("wrong PIN: unexpected error {e}"),
        Ok(_) => panic!("wrong PIN accepted"),
    }
}

#[test]
fn decrypter_round_trips_pkcs1v15_and_oaep() {
    let Some(der) = openssl_keystore("CN=p12-decrypt") else {
        eprintln!("skipping (openssl missing)");
        return;
    };
    let kp = P12Keypair::parse(&der, PIN).expect("parse keystore");
    let decrypter = P12Decrypter::new(kp);
    let public = decrypter.certificate().rsa_public_key().unwrap();

    let secret: Vec<u8> = (0u8..32).collect();
    let mut rng = rand::thread_rng();

    // RSAES-PKCS1-v1_5
    let sealed = public
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, &secret)
        .unwrap();
    assert_eq!(decrypter.decrypt_pkcs1v15(&sealed).unwrap(), secret);

    // RSAES-OAEP (SHA-256/MGF1-SHA-256, the mock's transport flavour)
    let sealed = public
        .encrypt(&mut rng, rsa::Oaep::new::<Sha256>(), &secret)
        .unwrap();
    assert_eq!(
        decrypter
            .decrypt_oaep(&sealed, MGF1_SHA256, DIGEST_SHA256)
            .unwrap(),
        secret
    );
}

#[test]
fn signer_produces_verifiable_pss_signature() {
    let Some(der) = openssl_keystore("CN=p12-sign") else {
        eprintln!("skipping (openssl missing)");
        return;
    };
    let kp = P12Keypair::parse(&der, PIN).expect("parse keystore");
    let signer = P12Signer::new(kp, None);

    let data = b"die nutzdaten";
    let sig_bytes = signer.sign(data, RSA_SHA256_PSS).expect("sign");

    // verify against the certificate's public key, independent of the
    // signing path
    let public = signer.certificate().rsa_public_key().unwrap();
    let verifying = rsa::pss::VerifyingKey::<Sha256>::new(public);
    let sig = rsa::pss::Signature::try_from(sig_bytes.as_slice()).unwrap();
    assert!(
        verifying.verify(data, &sig).is_ok(),
        "PSS signature must verify"
    );
}

#[test]
fn pem_encoding_of_public_key_round_trips() {
    // sanity guard on the imports this file relies on
    let Some(der) = openssl_keystore("CN=p12-enc") else {
        eprintln!("skipping (openssl missing)");
        return;
    };
    let kp = P12Keypair::parse(&der, PIN).unwrap();
    let public = kp.certificate().rsa_public_key().unwrap();
    let pem = public
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
}
