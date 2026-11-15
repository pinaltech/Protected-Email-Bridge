//! End-to-end OpenPGP checks with freshly generated Ed25519/X25519 keys.

use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
use pgp::crypto::ecc_curve::ECCCurve;

use protected_email_bridge::api::types::{Attachment, Message, MessageMetadata};
use protected_email_bridge::config::LocalArtifacts;
use protected_email_bridge::crypto::{self, KeyRing, UnlockedKey};
use protected_email_bridge::import::encrypt_for_import;
use protected_email_bridge::literal::decrypt_and_build;
use protected_email_bridge::mime::Part;
use protected_email_bridge::smtp::package::build_packages;
use protected_email_bridge::smtp::prefs::{SendPreferences, scheme};
use protected_email_bridge::util::b64;

fn gen_key(uid: &str, pass: &str) -> String {
    let mut enc = SubkeyParamsBuilder::default();
    enc.key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
        .can_sign(false)
        .can_encrypt(EncryptionCaps::All)
        .can_authenticate(false)
        .passphrase(Some(pass.into()));
    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id(uid.into())
        .passphrase(Some(pass.into()))
        .subkeys(vec![enc.build().unwrap()]);
    let key = params
        .build()
        .unwrap()
        .generate(rand08::thread_rng())
        .unwrap();
    key.to_armored_string(Default::default()).unwrap()
}

fn ring(uid: &str, pass: &str) -> KeyRing {
    let armored = gen_key(uid, pass);
    KeyRing::new(vec![
        UnlockedKey::unlock(&armored, pass.as_bytes()).unwrap(),
    ])
}

#[test]
fn unlock_requires_correct_passphrase() {
    let armored = gen_key("A <a@example.org>", "secret");
    assert!(UnlockedKey::unlock(&armored, b"secret").is_ok());
    assert!(UnlockedKey::unlock(&armored, b"wrong").is_err());
}

#[test]
fn encrypt_decrypt_sign_and_session_keys() {
    let r = ring("A <a@example.org>", "pw");
    let (bin, session) = r.encrypt(b"hello world", true, "").unwrap();
    let d = r.decrypt(&bin).unwrap();
    assert_eq!(d.data, b"hello world");
    let (sig, hash) = d.signature.expect("embedded signature");
    assert!(!sig.is_empty());
    assert_eq!(hash, "SHA-256");

    let (kp, data) = crypto::split_message(&bin).unwrap();
    assert!(!data.is_empty());
    let recovered = r.decrypt_session_key(&kp).unwrap();
    assert_eq!(&*recovered.key, &*session.key);
    assert_eq!(recovered.algorithm_name(), "aes256");

    // Re-encrypt the session key to another recipient and decrypt there.
    let other = ring("B <b@example.org>", "pw2");
    let pkesk = session
        .encrypt_to(&other.first().unwrap().public_key())
        .unwrap();
    let mut msg = pkesk.clone();
    msg.extend_from_slice(&data);
    assert_eq!(other.decrypt(&msg).unwrap().data, b"hello world");

    // Detached signatures.
    let sig = r.first().unwrap().sign_detached(b"data").unwrap();
    assert!(r.verify_detached(b"data", &sig).is_ok());
    assert!(r.verify_detached(b"other", &sig).is_err());
}

#[test]
fn literal_from_encrypted_message() {
    let r = ring("A <a@example.org>", "pw");
    let body = r.encrypt_armored(b"<p>Hi</p>", false).unwrap();
    let (att_bin, _) = r.encrypt(b"attachment bytes", false, "a.txt").unwrap();
    let (kp, data) = crypto::split_message(&att_bin).unwrap();
    let msg = Message {
        metadata: MessageMetadata {
            id: "m1".into(),
            subject: "Test".into(),
            time: 1_700_000_000,
            flags: 1,
            ..Default::default()
        },
        body,
        mime_type: "text/html".into(),
        attachments: vec![Attachment {
            id: "a1".into(),
            name: "a.txt".into(),
            mime_type: "text/plain".into(),
            disposition: "attachment".into(),
            key_packets: b64(&kp),
            ..Default::default()
        }],
        ..Default::default()
    };
    let (lit, failed) = decrypt_and_build(&msg, &r, vec![data], &LocalArtifacts::default());
    assert!(!failed);
    let p = Part::parse(&lit).unwrap();
    assert_eq!(p.children.len(), 2);
    assert_eq!(p.children[0].text(), "<p>Hi</p>");
    assert_eq!(p.children[1].decoded_body(), b"attachment bytes");

    // A key ring that cannot decrypt yields placeholders, not a failure.
    let wrong = ring("C <c@example.org>", "x");
    let (lit2, failed2) =
        decrypt_and_build(&msg, &wrong, vec![vec![0u8; 4]], &LocalArtifacts::default());
    assert!(!failed2);
    let s = String::from_utf8_lossy(&lit2);
    assert!(s.contains("This message could not be decrypted"));
    assert!(s.contains("a.txt.pgp"));
}

#[test]
fn import_encryption_per_part() {
    let r = ring("A <a@example.org>", "pw");
    let lit = b"From: a@example.org\r\nTo: b@example.org\r\nSubject: s\r\nContent-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\ncaf\xe9\r\n--XYZ\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\naGk=\r\n--XYZ--\r\n";
    let enc = encrypt_for_import(lit, &r).unwrap();
    let p = Part::parse(&enc).unwrap();
    assert_eq!(p.boundary.as_deref(), Some("XYZ"));
    let text = &p.children[0];
    assert!(
        text.header
            .get("Content-Type")
            .unwrap()
            .contains("charset=utf-8")
    );
    assert_eq!(r.decrypt(&text.body).unwrap().data, "café".as_bytes());
    let bin = &p.children[1];
    assert_eq!(r.decrypt(&bin.decoded_body()).unwrap().data, b"hi");
}

#[test]
fn packages() {
    let r = ring("A <a@example.org>", "pw");
    let other = ring("B <b@example.org>", "pw");
    let recips = vec![
        (
            "clear@ext.org".to_string(),
            SendPreferences {
                encrypt: false,
                sign: false,
                scheme: scheme::CLEAR,
                signature_type: 0,
                mime_type: "text/html".into(),
                pub_key: None,
                internal: false,
            },
        ),
        (
            "b@example.org".to_string(),
            SendPreferences {
                encrypt: true,
                sign: true,
                scheme: scheme::INTERNAL,
                signature_type: 1,
                mime_type: "text/html".into(),
                pub_key: Some(other.first().unwrap().public_key()),
                internal: true,
            },
        ),
    ];
    let pk = build_packages(&r, &recips, "<p>x</p>", "x", b"", &Default::default()).unwrap();
    assert_eq!(pk.len(), 1);
    assert_eq!(pk[0].scheme, scheme::CLEAR | scheme::INTERNAL);
    assert!(pk[0].body_key.is_some());
    assert!(pk[0].addresses["b@example.org"].body_key_packet.is_some());
}
