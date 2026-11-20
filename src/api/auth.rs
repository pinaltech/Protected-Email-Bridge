//! Authentication endpoints (§5, §8.1).

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::client::{ApiClient, Request};
use super::types::SessionInfo;
use crate::error::Result;
use crate::util::null_default;

/// FIDO2 options as returned by the Service.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Fido2Info {
    #[serde(default)]
    pub authentication_options: Option<Value>,
    #[serde(default, deserialize_with = "null_default")]
    pub registered_keys: Vec<Value>,
}

/// `2FA` object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TwoFactorInfo {
    /// Bitmask: 1 = TOTP, 2 = FIDO2.
    #[serde(default)]
    pub enabled: i64,
    #[serde(rename = "FIDO2", default)]
    pub fido2: Fido2Info,
}

impl TwoFactorInfo {
    pub fn totp(&self) -> bool {
        self.enabled & 1 != 0
    }
    pub fn fido2(&self) -> bool {
        self.enabled & 2 != 0
    }
    pub fn required(&self) -> bool {
        self.enabled != 0
    }
}

/// `POST /auth/v4/info` response (§5.1.1).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthInfo {
    pub version: i64,
    pub modulus: String,
    pub server_ephemeral: String,
    #[serde(default, deserialize_with = "null_default")]
    pub salt: String,
    #[serde(rename = "SRPSession")]
    pub srp_session: String,
    #[serde(rename = "2FA", default)]
    pub two_factor: TwoFactorInfo,
}

/// `POST /auth/v4` and `/auth/v4/refresh` response (§5.1.6).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthResponse {
    #[serde(rename = "UserID", default)]
    pub user_id: String,
    #[serde(rename = "UID", default)]
    pub uid: String,
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default, deserialize_with = "null_default")]
    pub server_proof: String,
    #[serde(default, deserialize_with = "null_default")]
    pub scope: String,
    #[serde(rename = "2FA", default)]
    pub two_factor: TwoFactorInfo,
    #[serde(default)]
    pub password_mode: i64,
}

/// FIDO2 assertion submitted in `/auth/v4/2fa` (§5.2.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Fido2Assertion {
    #[serde(rename = "AuthenticationOptions")]
    pub authentication_options: Option<Value>,
    #[serde(rename = "ClientData")]
    pub client_data: String,
    #[serde(rename = "AuthenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "Signature")]
    pub signature: String,
    #[serde(rename = "CredentialID")]
    pub credential_id: Option<Vec<u8>>,
}

pub(crate) fn empty_fido2() -> Value {
    json!({
        "AuthenticationOptions": null,
        "ClientData": "",
        "AuthenticatorData": "",
        "Signature": "",
        "CredentialID": null
    })
}

impl ApiClient {
    /// `POST /auth/v4/info`.
    pub async fn auth_info(&self, username: &str) -> Result<AuthInfo> {
        self.send_json(
            Request::post("/auth/v4/info")
                .unauthenticated()
                .json(json!({ "Username": username })),
        )
        .await
    }

    /// `POST /auth/v4` (SRP proof). Human verification headers are attached
    /// when present.
    pub async fn auth(
        &self,
        username: &str,
        client_ephemeral: &str,
        client_proof: &str,
        srp_session: &str,
    ) -> Result<AuthResponse> {
        let req = Request::post("/auth/v4").unauthenticated().json(json!({
            "Username": username,
            "ClientEphemeral": client_ephemeral,
            "ClientProof": client_proof,
            "SRPSession": srp_session,
            "FIDO2": empty_fido2(),
        }));
        let req = self.with_hv(req).await;
        self.send_json(req).await
    }

    /// `POST /auth/v4/2fa` with a TOTP code (§5.2.1).
    pub async fn auth_2fa_totp(&self, code: &str) -> Result<()> {
        self.send(Request::post("/auth/v4/2fa").json(json!({
            "TwoFactorCode": code,
            "FIDO2": empty_fido2(),
        })))
        .await?;
        Ok(())
    }

    /// `POST /auth/v4/2fa` with a FIDO2 assertion (§5.2.2).
    pub async fn auth_2fa_fido2(&self, assertion: &Fido2Assertion) -> Result<()> {
        self.send(Request::post("/auth/v4/2fa").json(json!({ "FIDO2": assertion })))
            .await?;
        Ok(())
    }

    /// `DELETE /auth/v4` — revoke the current session (§5.5.2).
    pub async fn logout(&self) -> Result<()> {
        self.send(Request::delete("/auth/v4")).await?;
        self.clear_tokens().await;
        Ok(())
    }

    /// `GET /auth/v4/sessions`.
    pub async fn list_sessions(&self) -> Result<Vec<SessionInfo>> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Sessions", default)]
            sessions: Vec<SessionInfo>,
        }
        Ok(self
            .send_json::<R>(Request::get("/auth/v4/sessions"))
            .await?
            .sessions)
    }

    /// `DELETE /auth/v4/sessions/{uid}`.
    pub async fn revoke_session(&self, uid: &str) -> Result<()> {
        self.send(Request::delete(format!("/auth/v4/sessions/{uid}")))
            .await?;
        Ok(())
    }

    /// `DELETE /auth/v4/sessions`.
    pub async fn revoke_all_sessions(&self) -> Result<()> {
        self.send(Request::delete("/auth/v4/sessions")).await?;
        Ok(())
    }

    /// `GET /auth/v4/modulus` → (Modulus, ModulusID).
    pub async fn auth_modulus(&self) -> Result<(String, String)> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Modulus")]
            modulus: String,
            #[serde(rename = "ModulusID")]
            modulus_id: String,
        }
        let r: R = self.send_json(Request::get("/auth/v4/modulus")).await?;
        Ok((r.modulus, r.modulus_id))
    }
}
