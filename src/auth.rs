//! Login flow, second factors, human verification and session resume (§5).

use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::api::auth::{AuthResponse, Fido2Assertion};
use crate::api::types::{Address, KeySalt, User};
use crate::api::{ApiClient, HumanVerification, SessionTokens};
use crate::crypto::{self, KeyRing};
use crate::error::{Error, Result};
use crate::keys;
use crate::srp;
use crate::util::{b64, b64url_np};

/// Result of the SRP phase: an authenticated session that may still need a
/// second factor and/or the mailbox password.
pub struct PendingLogin {
    client: ApiClient,
    pub username: String,
    pub auth: AuthResponse,
    password: Zeroizing<Vec<u8>>,
    two_factor_done: bool,
}

/// A fully completed login (§5.4 step 7).
pub struct LoggedIn {
    pub user: User,
    pub addresses: Vec<Address>,
    pub tokens: SessionTokens,
    /// Salted key passphrase for the primary user key (store this, never the
    /// plaintext password).
    pub salted_key_passphrase: Zeroizing<Vec<u8>>,
    pub user_keyring: KeyRing,
}

fn hv_from_error(e: &Error) -> Option<Error> {
    let api = e.api()?;
    if api.code != 9001 {
        return None;
    }
    let d = api.details.as_ref()?;
    let methods = d
        .get("HumanVerificationMethods")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let token = d
        .get("HumanVerificationToken")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Some(Error::HumanVerificationRequired { methods, token })
}

/// Perform the SRP login (§5.1). `is_connected_user` reports whether a
/// UserID already belongs to a connected Account (§5.1.7). Pass the solved
/// human-verification token, if any, in `hv` (§5.3).
pub async fn login(
    client: &ApiClient,
    username: &str,
    password: &[u8],
    hv: Option<HumanVerification>,
    is_connected_user: impl Fn(&str) -> bool,
) -> Result<PendingLogin> {
    client.set_human_verification(hv).await;
    let cfg = client.config().clone();

    // The Service refuses a login outside a session for some app
    // versions ("Invalid access token"), so the login runs in an anonymous
    // one (§5.1.0). A retry (after human verification) keeps the one it
    // has. A Service without anonymous sessions is logged in to without.
    if client.tokens().await.uid.is_empty() {
        match client.create_anonymous_session().await {
            Ok(tokens) => client.set_tokens(tokens).await,
            Err(Error::Api(e)) if e.status == 404 || e.status == 405 => {}
            Err(e) => return Err(e),
        }
    }

    let info = client.auth_info(username).await?;
    let signing_key = crypto::parse_public_key(cfg.modulus_signing_key.as_bytes())?;
    let modulus = srp::verify_modulus(&info.modulus, &signing_key)?;
    let salt = if info.version >= 3 {
        info.salt.as_str()
    } else {
        ""
    };
    let hashed = srp::hash_password(
        info.version,
        password,
        username,
        salt,
        &modulus,
        &cfg.srp_salt_suffix,
    )?;
    let server_eph = crate::util::b64_decode(&info.server_ephemeral)?;
    let proofs = srp::generate_proofs(&modulus, &server_eph, &hashed)?;

    let auth = match client
        .auth(
            username,
            &proofs.client_ephemeral,
            &proofs.client_proof,
            &info.srp_session,
        )
        .await
    {
        Ok(a) => a,
        Err(e) => return Err(hv_from_error(&e).unwrap_or(e)),
    };
    srp::verify_server_proof(&proofs.expected_server_proof, &auth.server_proof)?;

    client
        .set_tokens(SessionTokens {
            uid: auth.uid.clone(),
            access_token: auth.access_token.clone(),
            refresh_token: auth.refresh_token.clone(),
        })
        .await;

    if is_connected_user(&auth.user_id) {
        let _ = client.logout().await;
        return Err(Error::AlreadyLoggedIn);
    }

    Ok(PendingLogin {
        client: client.clone(),
        username: username.to_string(),
        two_factor_done: auth.two_factor.enabled == 0,
        auth,
        password: Zeroizing::new(password.to_vec()),
    })
}

impl PendingLogin {
    /// Whether a second factor must be submitted.
    pub fn needs_second_factor(&self) -> bool {
        !self.two_factor_done
    }

    /// Whether a separate mailbox password is needed (`PasswordMode = 2`).
    pub fn needs_mailbox_password(&self) -> bool {
        self.auth.password_mode == 2
    }

    /// Submit a TOTP code (§5.2.1).
    pub async fn submit_totp(&mut self, code: &str) -> Result<()> {
        self.client.auth_2fa_totp(code).await?;
        self.two_factor_done = true;
        Ok(())
    }

    /// Prepare a FIDO2 assertion request (§5.2.2 steps 1–3).
    pub fn fido2_request(&self) -> Result<Fido2Request> {
        let opts = self
            .auth
            .two_factor
            .fido2
            .authentication_options
            .clone()
            .ok_or_else(|| Error::Auth("no FIDO2 authentication options".into()))?;
        Fido2Request::from_options(opts)
    }

    /// Submit an authenticator response (§5.2.2 steps 4–5).
    pub async fn submit_fido2(
        &mut self,
        req: &Fido2Request,
        authenticator_data_cbor: &[u8],
        signature: &[u8],
        credential_id: &[u8],
    ) -> Result<()> {
        let auth_data = cbor_byte_string(authenticator_data_cbor)
            .unwrap_or_else(|| authenticator_data_cbor.to_vec());
        let assertion = Fido2Assertion {
            authentication_options: Some(req.options.clone()),
            client_data: b64(&req.client_data_json),
            authenticator_data: b64(&auth_data),
            signature: b64(signature),
            credential_id: Some(credential_id.to_vec()),
        };
        self.client.auth_2fa_fido2(&assertion).await?;
        self.two_factor_done = true;
        Ok(())
    }

    /// Complete the login (§5.4). Pass the mailbox password when
    /// [`needs_mailbox_password`](Self::needs_mailbox_password) is true.
    ///
    /// If no key unlocks, [`Error::KeyUnlock`] is returned and the session is
    /// kept open so that the caller may retry with another mailbox password.
    pub async fn finish(&self, mailbox_password: Option<&[u8]>) -> Result<LoggedIn> {
        if !self.two_factor_done {
            return Err(Error::Auth("second factor required".into()));
        }
        let key_password: &[u8] = if self.needs_mailbox_password() {
            mailbox_password.ok_or_else(|| Error::Auth("mailbox password required".into()))?
        } else {
            &self.password
        };
        let user = self.client.get_user().await?;
        self.client.set_human_verification(None).await;
        match self.finish_inner(user, key_password).await {
            Ok(done) => Ok(done),
            Err(Error::KeyUnlock) => Err(Error::KeyUnlock),
            Err(e) => {
                let _ = self.client.logout().await;
                Err(e)
            }
        }
    }

    async fn finish_inner(&self, user: User, key_password: &[u8]) -> Result<LoggedIn> {
        let salts: Vec<KeySalt> = self.client.get_key_salts().await?;
        let primary =
            keys::primary_key(&user.keys).ok_or_else(|| Error::Auth("user has no keys".into()))?;
        let salted = keys::salted_key_passphrase(key_password, &salts, &primary.id)?;
        let ring = keys::unlock_user_keyring(&user.keys, &salted)?;
        let addresses = self.client.get_addresses().await?;
        Ok(LoggedIn {
            user,
            addresses,
            tokens: self.client.tokens().await,
            salted_key_passphrase: salted,
            user_keyring: ring,
        })
    }

    /// Abandon the login and revoke the session.
    pub async fn abort(self) -> Result<()> {
        self.client.logout().await
    }
}

/// A prepared WebAuthn assertion request (§5.2.2).
#[derive(Debug, Clone)]
pub struct Fido2Request {
    /// The `AuthenticationOptions` object, echoed back on submit.
    pub options: Value,
    pub rp_id: String,
    pub client_data_json: Vec<u8>,
    pub client_data_hash: [u8; 32],
    pub allowed_credentials: Vec<Vec<u8>>,
}

impl Fido2Request {
    pub fn from_options(options: Value) -> Result<Self> {
        let pk = options
            .get("publicKey")
            .ok_or_else(|| Error::Auth("FIDO2 options lack publicKey".into()))?;
        let rp_id = pk
            .get("rpId")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Auth("FIDO2 options lack rpId".into()))?
            .to_string();
        let challenge = int_array(pk.get("challenge"))
            .ok_or_else(|| Error::Auth("FIDO2 options lack challenge".into()))?;
        let allowed: Vec<Vec<u8>> = pk
            .get("allowCredentials")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|c| int_array(c.get("id"))).collect())
            .unwrap_or_default();
        if allowed.is_empty() {
            return Err(Error::Auth("no allowed FIDO2 credentials".into()));
        }
        let client_data = serde_json::json!({
            "challenge": b64url_np(&challenge),
            "origin": format!("https://{rp_id}"),
            "type": "webauthn.get",
        });
        let client_data_json = serde_json::to_vec(&client_data)?;
        let client_data_hash: [u8; 32] = Sha256::digest(&client_data_json).into();
        Ok(Self {
            options,
            rp_id,
            client_data_json,
            client_data_hash,
            allowed_credentials: allowed,
        })
    }
}

fn int_array(v: Option<&Value>) -> Option<Vec<u8>> {
    v?.as_array()?
        .iter()
        .map(|x| x.as_u64().and_then(|n| u8::try_from(n).ok()))
        .collect()
}

/// Decode a CBOR byte string (major type 2), as returned by authenticators.
pub fn cbor_byte_string(data: &[u8]) -> Option<Vec<u8>> {
    let first = *data.first()?;
    if first >> 5 != 2 {
        return None;
    }
    let info = first & 0x1f;
    let (len, off) = match info {
        0..=23 => (info as usize, 1),
        24 => (*data.get(1)? as usize, 2),
        25 => (
            u16::from_be_bytes([*data.get(1)?, *data.get(2)?]) as usize,
            3,
        ),
        26 => (
            u32::from_be_bytes([*data.get(1)?, *data.get(2)?, *data.get(3)?, *data.get(4)?])
                as usize,
            5,
        ),
        _ => return None,
    };
    data.get(off..off + len).map(<[u8]>::to_vec)
}

/// Resume a stored Account at start-up (§5.5.1). On error code 10013 the
/// caller MUST clear the stored UID and RefreshToken; this is signalled by
/// [`Error::Deauthenticated`].
pub async fn resume(client: &ApiClient, uid: &str, refresh_token: &str) -> Result<SessionTokens> {
    client
        .set_tokens(SessionTokens {
            uid: uid.to_string(),
            access_token: String::new(),
            refresh_token: refresh_token.to_string(),
        })
        .await;
    match client.refresh().await {
        Ok(()) => Ok(client.tokens().await),
        Err(e) if e.api().is_some_and(|a| a.code == 10013) => {
            client.clear_tokens().await;
            Err(Error::Deauthenticated)
        }
        Err(e) => Err(e),
    }
}

/// Re-unlock the user's keys from a stored salted key passphrase.
pub async fn unlock_from_passphrase(client: &ApiClient, salted: &[u8]) -> Result<(User, KeyRing)> {
    let user = client.get_user().await?;
    let ring = keys::unlock_user_keyring(&user.keys, salted)?;
    Ok((user, ring))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::test_support;
    use std::sync::Arc;

    /// The login runs in an anonymous session (§5.1.0): the Service
    /// refuses the info request without one, as it does for some app
    /// versions. A Service without anonymous sessions is asked without.
    #[tokio::test]
    async fn login_runs_in_an_anonymous_session() {
        for sessions in [true, false] {
            let stub = test_support::start(Arc::new(move |s| match s.path.as_str() {
                "/auth/v4/sessions" if sessions => (
                    200,
                    r#"{"Code":1000,"UID":"anon-1","AccessToken":"a","RefreshToken":"r","TokenType":"Bearer","Scopes":[]}"#.into(),
                ),
                "/auth/v4/sessions" => (404, r#"{"Code":404,"Error":"Not found"}"#.into()),
                // An unsigned modulus: the login stops after this request.
                "/auth/v4/info" if s.uid.as_deref() == Some("anon-1") || !sessions => (
                    200,
                    r#"{"Code":1000,"Version":4,"Modulus":"x","ServerEphemeral":"","Salt":"","SRPSession":"s"}"#.into(),
                ),
                _ => (401, r#"{"Code":401,"Error":"Invalid access token"}"#.into()),
            }))
            .await;
            let client = ApiClient::new(test_support::config(&stub.base)).unwrap();
            let error = login(&client, "ana", b"pw", None, |_| false)
                .await
                .err()
                .expect("the unsigned modulus is refused");
            assert_ne!(error.status(), Some(401), "{error}");
            let seen = stub.seen.lock().unwrap().clone();
            let paths: Vec<&str> = seen.iter().map(|s| s.path.as_str()).collect();
            assert_eq!(paths, ["/auth/v4/sessions", "/auth/v4/info"]);
            assert_eq!(seen[0].uid, None);
            let expected = sessions.then(|| "anon-1".to_string());
            assert_eq!(seen[1].uid, expected);
            // A repeated login keeps the session it has.
            if sessions {
                let _ = login(&client, "ana", b"pw", None, |_| false).await;
                let seen = stub.seen.lock().unwrap();
                assert_eq!(
                    seen.iter()
                        .filter(|s| s.path == "/auth/v4/sessions")
                        .count(),
                    1
                );
            }
        }
    }

    #[test]
    fn cbor() {
        assert_eq!(cbor_byte_string(&[0x43, 1, 2, 3]), Some(vec![1, 2, 3]));
        assert_eq!(cbor_byte_string(&[0x58, 2, 9, 9]), Some(vec![9, 9]));
        assert_eq!(cbor_byte_string(&[0x01]), None);
    }

    #[test]
    fn fido_request() {
        let opts = serde_json::json!({"publicKey": {"rpId": "example.org", "challenge": [1,2,3], "allowCredentials": [{"id": [4,5]}]}});
        let r = Fido2Request::from_options(opts).unwrap();
        assert_eq!(r.allowed_credentials, vec![vec![4, 5]]);
        let cd: Value = serde_json::from_slice(&r.client_data_json).unwrap();
        assert_eq!(cd["origin"], "https://example.org");
        assert_eq!(cd["challenge"], "AQID");
    }
}
