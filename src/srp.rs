//! SRP-6a variant used for password authentication (§5.1).
//!
//! All big integers are 2048 bits, serialised little-endian and zero-padded
//! to 256 octets.
//!
//! Arithmetic split (§5.1.5 "constant-time arithmetic is RECOMMENDED for
//! every operation that involves a, x or S"):
//!
//! * Public values only (N, B, k, u, group validation, Miller–Rabin) use
//!   `num-bigint`, which is variable-time.
//! * Everything that touches the secret ephemeral `a`, the password hash `x`
//!   or the shared secret `S` uses fixed-width 2048-bit `crypto-bigint`
//!   Montgomery arithmetic, which is constant-time, and is zeroized after use.

use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{Odd, U2048};
use md5::Md5;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use pgp::composed::SignedPublicKey;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::config::limits::{BCRYPT_COST, SRP_BITS, SRP_LEN};
use crate::crypto;
use crate::error::{Error, Result};
use crate::util::{b64, b64_decode, random_bytes};

const BCRYPT_ALPHABET: &[u8; 64] =
    b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// `H(x) = SHA-512(x‖0) ‖ SHA-512(x‖1) ‖ SHA-512(x‖2) ‖ SHA-512(x‖3)`.
pub fn expand_hash(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    for i in 0u8..4 {
        let mut h = Sha512::new();
        h.update(data);
        h.update([i]);
        out.extend_from_slice(&h.finalize());
    }
    out
}

/// Unpadded radix-64 encoding in the bcrypt alphabet.
pub fn bcrypt_r64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        let chars = chunk.len() + 1;
        for i in 0..chars {
            let idx = (n >> (18 - 6 * i)) & 0x3f;
            out.push(BCRYPT_ALPHABET[idx as usize] as char);
        }
    }
    out
}

/// Decode a bcrypt radix-64 string. Trailing partial bits are discarded.
pub fn bcrypt_r64_decode(s: &str) -> Result<Vec<u8>> {
    let mut vals = Vec::with_capacity(s.len());
    for c in s.bytes() {
        let v = BCRYPT_ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| Error::Srp(format!("invalid bcrypt salt character {:?}", c as char)))?;
        vals.push(v as u32);
    }
    let mut out = Vec::new();
    for chunk in vals.chunks(4) {
        let mut n = 0u32;
        for (i, v) in chunk.iter().enumerate() {
            n |= v << (18 - 6 * i);
        }
        let bytes = chunk.len() * 6 / 8;
        for i in 0..bytes {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    Ok(out)
}

/// Full 60-character `$2y$10$...` bcrypt output with a raw 16-octet salt.
pub fn bcrypt_raw_salt(password: &[u8], salt: [u8; 16]) -> Result<Zeroizing<String>> {
    let parts = bcrypt::hash_with_salt(password, BCRYPT_COST, salt)
        .map_err(|e| Error::Srp(format!("bcrypt: {e}")))?;
    Ok(Zeroizing::new(
        parts.format_for_version(bcrypt::Version::TwoY),
    ))
}

/// bcrypt with a radix-64 salt string; the leading 22 characters are used.
pub fn bcrypt_r64_salt(password: &[u8], salt: &str) -> Result<Zeroizing<String>> {
    let s: String = salt.chars().take(22).collect();
    if s.len() < 22 {
        return Err(Error::Srp("bcrypt salt too short".into()));
    }
    let raw = bcrypt_r64_decode(&s)?;
    let mut salt16 = [0u8; 16];
    salt16.copy_from_slice(&raw[..16]);
    bcrypt_raw_salt(password, salt16)
}

/// Compute the hashed password x̂ (§5.1.3).
pub fn hash_password(
    version: i64,
    password: &[u8],
    username: &str,
    salt_b64: &str,
    modulus: &[u8],
    salt_suffix: &[u8; 6],
) -> Result<Zeroizing<Vec<u8>>> {
    let bcrypted = match version {
        3 | 4 => {
            let s = b64_decode(salt_b64)?;
            let mut full = s.clone();
            full.extend_from_slice(salt_suffix);
            if full.len() != 16 {
                return Err(Error::Srp(format!(
                    "unexpected SRP salt length {}",
                    s.len()
                )));
            }
            let mut salt16 = [0u8; 16];
            salt16.copy_from_slice(&full);
            debug_assert_eq!(bcrypt_r64_encode(&salt16).len(), 22);
            bcrypt_raw_salt(password, salt16)?
        }
        2 => {
            let u: String = username
                .chars()
                .filter(|c| !matches!(c, '-' | '.' | '_'))
                .collect::<String>()
                .to_lowercase();
            bcrypt_v1(password, &u)?
        }
        1 => bcrypt_v1(password, username)?,
        0 => {
            let mut h = Sha512::new();
            h.update(username.to_lowercase().as_bytes());
            h.update(password);
            let p2 = Zeroizing::new(b64(h.finalize()));
            bcrypt_v1(p2.as_bytes(), username)?
        }
        v => return Err(Error::Srp(format!("unsupported password version {v}"))),
    };
    let mut input = Zeroizing::new(bcrypted.as_bytes().to_vec());
    input.extend_from_slice(modulus);
    Ok(Zeroizing::new(expand_hash(&input)))
}

fn bcrypt_v1(password: &[u8], username: &str) -> Result<Zeroizing<String>> {
    let digest = Md5::digest(username.to_lowercase().as_bytes());
    let salt = hex::encode(digest);
    bcrypt_r64_salt(password, &salt)
}

/// Verify the clear-signed modulus (§5.1.2) and return the modulus octets.
pub fn verify_modulus(signed: &str, signing_key: &SignedPublicKey) -> Result<Vec<u8>> {
    let text = crypto::verify_cleartext(signed, signing_key)?;
    let n = b64_decode(text.trim())?;
    if n.len() != SRP_LEN {
        return Err(Error::Srp(format!("modulus has {} octets", n.len())));
    }
    Ok(n)
}

fn le_pad(n: &BigUint) -> Vec<u8> {
    let mut v = n.to_bytes_le();
    v.resize(SRP_LEN, 0);
    v
}

fn random_biguint_below(bound: &BigUint) -> BigUint {
    loop {
        let bytes = random_bytes(SRP_LEN);
        let mut n = BigUint::from_bytes_le(&bytes);
        n >>= (SRP_LEN as u64 * 8).saturating_sub(bound.bits());
        if &n < bound {
            return n;
        }
    }
}

/// Miller–Rabin probable-prime test with `rounds` random bases.
pub fn is_probably_prime(n: &BigUint, rounds: usize) -> bool {
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);
    if n < &two {
        return false;
    }
    if n == &two || n == &three {
        return true;
    }
    if n.is_even() {
        return false;
    }
    for p in [3u32, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let p = BigUint::from(p);
        if n == &p {
            return true;
        }
        if (n % &p).is_zero() {
            return false;
        }
    }
    let n_minus_1 = n - 1u32;
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }
    let range = n - &three; // bases in [2, n-2]
    'outer: for _ in 0..rounds {
        let a = random_biguint_below(&range) + &two;
        let mut x = a.modpow(&d, n);
        if x.is_one() || x == n_minus_1 {
            continue;
        }
        for _ in 1..r {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

/// Validate the SRP group and server ephemeral (§5.1.4).
pub fn validate_parameters(n: &BigUint, b: &BigUint) -> Result<()> {
    let g = BigUint::from(2u32);
    if n.bits() != SRP_BITS {
        return Err(Error::Srp("modulus is not 2048 bits".into()));
    }
    let low3 = (n % 8u32).to_u32_digits().first().copied().unwrap_or(0);
    if low3 != 3 {
        return Err(Error::Srp("modulus is not 3 mod 8".into()));
    }
    let n_minus_1 = n - 1u32;
    let q = &n_minus_1 >> 1;
    if !is_probably_prime(&q, 10) {
        return Err(Error::Srp("(N-1)/2 is not prime".into()));
    }
    if g.modpow(&q, n) != n_minus_1 {
        return Err(Error::Srp("generator check failed".into()));
    }
    if !(b > &BigUint::one() && b < &n_minus_1) {
        return Err(Error::Srp("server ephemeral out of range".into()));
    }
    Ok(())
}

/// Output of the proof computation.
#[derive(Debug, Clone)]
pub struct SrpProofs {
    /// B64(Â).
    pub client_ephemeral: String,
    /// B64(M1).
    pub client_proof: String,
    /// M2, compared with the decoded `ServerProof`.
    pub expected_server_proof: Vec<u8>,
}

/// Compute the client ephemeral and proofs (§5.1.5).
pub fn generate_proofs(
    modulus: &[u8],
    server_ephemeral: &[u8],
    hashed_password: &[u8],
) -> Result<SrpProofs> {
    generate_proofs_with(modulus, server_ephemeral, hashed_password, random_ephemeral)
}

/// Random 256 octets for a candidate `a`.
fn random_ephemeral() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(random_bytes(SRP_LEN))
}

/// Constant-time Montgomery context for the group modulus.
struct Group {
    params: FixedMontyParams<{ U2048::LIMBS }>,
    n_minus_1: U2048,
}

impl Group {
    fn new(modulus_le: &[u8]) -> Result<Self> {
        let n = U2048::from_le_slice(&pad_le(modulus_le)?);
        let odd = Odd::new(n)
            .into_option()
            .ok_or_else(|| Error::Srp("modulus is even".into()))?;
        Ok(Self {
            params: FixedMontyParams::new(odd),
            n_minus_1: n.wrapping_sub(&U2048::ONE),
        })
    }

    fn elem(&self, v: &U2048) -> FixedMontyForm<{ U2048::LIMBS }> {
        FixedMontyForm::new(v, &self.params)
    }
}

/// Zero-extend a little-endian value to exactly 256 octets.
fn pad_le(v: &[u8]) -> Result<Vec<u8>> {
    if v.len() > SRP_LEN && v[SRP_LEN..].iter().any(|b| *b != 0) {
        return Err(Error::Srp("value exceeds 2048 bits".into()));
    }
    let mut out = v[..v.len().min(SRP_LEN)].to_vec();
    out.resize(SRP_LEN, 0);
    Ok(out)
}

/// Proof computation with an injectable source of candidate `a` values
/// (used by tests to compare against a reference implementation).
fn generate_proofs_with(
    modulus: &[u8],
    server_ephemeral: &[u8],
    hashed_password: &[u8],
    next_a: impl FnMut() -> Zeroizing<Vec<u8>>,
) -> Result<SrpProofs> {
    let n = BigUint::from_bytes_le(modulus);
    let b = BigUint::from_bytes_le(server_ephemeral);
    validate_parameters(&n, &b)?;
    compute_proofs(modulus, server_ephemeral, hashed_password, next_a)
}

/// Proof computation for already-validated parameters.
fn compute_proofs(
    modulus: &[u8],
    server_ephemeral: &[u8],
    hashed_password: &[u8],
    mut next_a: impl FnMut() -> Zeroizing<Vec<u8>>,
) -> Result<SrpProofs> {
    // --- Public values: variable-time is fine. ---
    let n = BigUint::from_bytes_le(modulus);
    let b = BigUint::from_bytes_le(server_ephemeral);
    let g = BigUint::from(2u32);
    let n_minus_1 = &n - 1u32;
    let mut kin = le_pad(&g);
    kin.extend_from_slice(&le_pad(&n));
    let k = BigUint::from_bytes_le(&expand_hash(&kin)) % &n;
    if !(k > BigUint::one() && k < n_minus_1) {
        return Err(Error::Srp("invalid multiplier k".into()));
    }
    let b_hat = le_pad(&b);

    // --- Secret values: constant-time 2048-bit Montgomery arithmetic. ---
    let grp = Group::new(modulus)?;
    let g_m = grp.elem(&U2048::from_u8(2));
    let lower = U2048::from_u16(4096);

    let (mut a, a_hat, u_ct) = loop {
        let bytes = next_a();
        let mut cand = U2048::from_le_slice(&pad_le(&bytes)?);
        // Accept only 4096 < a < N−1 (comparisons are constant-time).
        if !(cand > lower && cand < grp.n_minus_1) {
            cand.zeroize();
            continue;
        }
        let a_hat = g_m.pow(&cand).retrieve().to_le_bytes().as_ref().to_vec();
        let mut uin = a_hat.clone();
        uin.extend_from_slice(&b_hat);
        let u_hash = expand_hash(&uin);
        let u = U2048::from_le_slice(&u_hash);
        if u == U2048::ZERO {
            cand.zeroize();
            continue;
        }
        break (cand, a_hat, u);
    };

    let mut x = U2048::from_le_slice(&pad_le(hashed_password)?);
    let k_m = grp.elem(&U2048::from_le_slice(&le_pad(&k)));
    let b_m = grp.elem(&U2048::from_le_slice(&b_hat));

    // base = (B − k·g^x) mod N
    let mut gx = g_m.pow(&x);
    let mut kgx = k_m.mul(&gx);
    let mut base = b_m.sub(&kgx);

    // S = base^((u·x + a) mod (N−1)) mod N.
    // N is a validated prime, so by Fermat base^(N−1) ≡ 1 for base ≢ 0 and
    // the exponent need not be reduced: S = (base^x)^u · base^a. This avoids
    // a wide multiplication and modular reduction of secret values. (For
    // base ≡ 0 both forms give 0 except when u·x + a ≡ 0 (mod N−1), which
    // occurs with negligible probability.)
    let mut bx = base.pow(&x);
    let mut bxu = bx.pow(&u_ct);
    let mut ba = base.pow(&a);
    let mut s_m = bxu.mul(&ba);
    let s_hat = Zeroizing::new(s_m.retrieve().to_le_bytes().as_ref().to_vec());

    for v in [
        &mut gx, &mut kgx, &mut base, &mut bx, &mut bxu, &mut ba, &mut s_m,
    ] {
        v.zeroize();
    }
    a.zeroize();
    x.zeroize();

    let mut m1in = Zeroizing::new(a_hat.clone());
    m1in.extend_from_slice(&b_hat);
    m1in.extend_from_slice(&s_hat);
    let m1 = expand_hash(&m1in);

    let mut m2in = Zeroizing::new(a_hat.clone());
    m2in.extend_from_slice(&m1);
    m2in.extend_from_slice(&s_hat);
    let m2 = expand_hash(&m2in);

    Ok(SrpProofs {
        client_ephemeral: b64(&a_hat),
        client_proof: b64(&m1),
        expected_server_proof: m2,
    })
}

/// Compare the server proof in constant time.
pub fn verify_server_proof(expected: &[u8], server_proof_b64: &str) -> Result<()> {
    use subtle::ConstantTimeEq;
    let got = b64_decode(server_proof_b64)?;
    if got.len() == expected.len() && bool::from(got.ct_eq(expected)) {
        Ok(())
    } else {
        Err(Error::Srp("server proof mismatch".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r64_roundtrip() {
        let data: Vec<u8> = (0u8..16).collect();
        let enc = bcrypt_r64_encode(&data);
        assert_eq!(enc.len(), 22);
        assert_eq!(bcrypt_r64_decode(&enc).unwrap(), data);
    }

    #[test]
    fn r64_matches_bcrypt_crate() {
        let salt = [7u8; 16];
        let full = bcrypt_raw_salt(b"pw", salt).unwrap();
        assert_eq!(&full[7..29], bcrypt_r64_encode(&salt));
        assert_eq!(full.len(), 60);
        assert!(full.starts_with("$2y$10$"));
    }

    #[test]
    fn expand_hash_len() {
        assert_eq!(expand_hash(b"abc").len(), 256);
    }

    /// RFC 3526 2048-bit MODP prime (a safe prime; used only to exercise
    /// the arithmetic — it is ≡ 7 mod 8, so it fails the §5.1.4 checks).
    const RFC3526_P: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

    fn group() -> BigUint {
        let n = BigUint::parse_bytes(RFC3526_P.as_bytes(), 16).unwrap();
        assert_eq!(n.bits(), 2048);
        assert!(is_probably_prime(&n, 5), "test prime mistyped");
        n
    }

    /// Reference implementation of §5.1.5 exactly as written, variable-time.
    fn reference_s(n: &BigUint, b: &BigUint, x: &BigUint, a: &BigUint, a_hat: &[u8]) -> Vec<u8> {
        let g = BigUint::from(2u32);
        let mut kin = le_pad(&g);
        kin.extend_from_slice(&le_pad(n));
        let k = BigUint::from_bytes_le(&expand_hash(&kin)) % n;
        let mut uin = a_hat.to_vec();
        uin.extend_from_slice(&le_pad(b));
        let u = BigUint::from_bytes_le(&expand_hash(&uin));
        let base = (b + n - (&k * g.modpow(x, n)) % n) % n;
        let exp = (&u * x + a) % (n - 1u32);
        le_pad(&base.modpow(&exp, n))
    }

    #[test]
    fn constant_time_path_matches_reference_and_server() {
        let n = group();
        let n_hat = le_pad(&n);
        let g = BigUint::from(2u32);
        let x_hat = expand_hash(b"password-hash-input");
        let x = BigUint::from_bytes_le(&x_hat);

        // Simulated server: v = g^x, B = k·v + g^b.
        let mut kin = le_pad(&g);
        kin.extend_from_slice(&n_hat);
        let k = BigUint::from_bytes_le(&expand_hash(&kin)) % &n;
        let v = g.modpow(&x, &n);
        let b_secret = BigUint::from_bytes_le(&random_bytes(64));
        let b = (&k * &v + g.modpow(&b_secret, &n)) % &n;
        let b_hat = le_pad(&b);

        // Fixed client ephemeral so the reference can reproduce it; the
        // first candidate (too small) must be rejected.
        let a_bytes = random_bytes(SRP_LEN - 1);
        let mut feed = vec![Zeroizing::new(vec![1u8]), Zeroizing::new(a_bytes.clone())].into_iter();
        let proofs = compute_proofs(&n_hat, &b_hat, &x_hat, || feed.next().unwrap()).unwrap();

        let a = BigUint::from_bytes_le(&a_bytes);
        let a_hat = b64_decode(&proofs.client_ephemeral).unwrap();
        assert_eq!(a_hat, le_pad(&g.modpow(&a, &n)));

        // Client S equals the spec's reference formula.
        let s_ref = reference_s(&n, &b, &x, &a, &a_hat);
        let mut m1in = a_hat.clone();
        m1in.extend_from_slice(&b_hat);
        m1in.extend_from_slice(&s_ref);
        assert_eq!(b64(expand_hash(&m1in)), proofs.client_proof);

        // Server-side S = (A·v^u)^b agrees, and M2 verifies.
        let mut uin = a_hat.clone();
        uin.extend_from_slice(&b_hat);
        let u = BigUint::from_bytes_le(&expand_hash(&uin));
        let a_big = BigUint::from_bytes_le(&a_hat);
        let s_server = le_pad(&((a_big * v.modpow(&u, &n)) % &n).modpow(&b_secret, &n));
        assert_eq!(s_server, s_ref);
        let m1 = expand_hash(&m1in);
        let mut m2in = a_hat.clone();
        m2in.extend_from_slice(&m1);
        m2in.extend_from_slice(&s_server);
        let server_proof = b64(expand_hash(&m2in));
        assert!(verify_server_proof(&proofs.expected_server_proof, &server_proof).is_ok());
        assert!(verify_server_proof(&proofs.expected_server_proof, &b64([0u8; 256])).is_err());
    }

    #[test]
    fn validation_rejects_bad_groups() {
        let n = group(); // ≡ 7 mod 8
        assert!(validate_parameters(&n, &BigUint::from(5u32)).is_err());
        let b = BigUint::from(5u32);
        assert!(generate_proofs(&le_pad(&n), &le_pad(&b), &[0u8; 256]).is_err());
    }

    #[test]
    fn primes() {
        assert!(is_probably_prime(&BigUint::from(1_000_000_007u64), 10));
        assert!(!is_probably_prime(&BigUint::from(1_000_000_008u64), 10));
        assert!(!is_probably_prime(&BigUint::from(561u32), 10));
    }
}
