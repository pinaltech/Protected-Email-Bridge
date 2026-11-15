//! Users, addresses, keys, labels, events and settings endpoints (§8.2–§8.5,
//! §8.12).

use serde::Deserialize;
use serde_json::json;

use super::client::{ApiClient, Request};
use super::types::*;
use crate::config::limits;
use crate::error::{Error, Result};
use crate::util::null_default;

impl ApiClient {
    /// `GET /core/v4/users`. Human verification headers are attached when
    /// present (first user fetch after login, §5.3).
    pub async fn get_user(&self) -> Result<User> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "User")]
            user: User,
        }
        let req = self.with_hv(Request::get("/core/v4/users")).await;
        Ok(self.send_json::<R>(req).await?.user)
    }

    /// `GET /core/v4/addresses`, sorted by ascending `Order`.
    pub async fn get_addresses(&self) -> Result<Vec<Address>> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Addresses", default, deserialize_with = "null_default")]
            addresses: Vec<Address>,
        }
        let mut a = self
            .send_json::<R>(Request::get("/core/v4/addresses"))
            .await?
            .addresses;
        sort_addresses(&mut a);
        Ok(a)
    }

    /// `GET /core/v4/addresses/{id}`.
    pub async fn get_address(&self, id: &str) -> Result<Address> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Address")]
            address: Address,
        }
        Ok(self
            .send_json::<R>(Request::get(format!("/core/v4/addresses/{id}")))
            .await?
            .address)
    }

    /// `GET /core/v4/keys/salts`.
    pub async fn get_key_salts(&self) -> Result<Vec<KeySalt>> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "KeySalts", default, deserialize_with = "null_default")]
            key_salts: Vec<KeySalt>,
        }
        Ok(self
            .send_json::<R>(Request::get("/core/v4/keys/salts"))
            .await?
            .key_salts)
    }

    /// `GET /core/v4/keys?Email=` (§6.4).
    pub async fn get_public_keys(&self, email: &str) -> Result<PublicKeys> {
        self.send_json(Request::get("/core/v4/keys").query("Email", email))
            .await
    }

    /// `GET /core/v4/labels?Type=<n>`.
    pub async fn get_labels(&self, kind: i64) -> Result<Vec<Label>> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Labels", default, deserialize_with = "null_default")]
            labels: Vec<Label>,
        }
        Ok(self
            .send_json::<R>(Request::get("/core/v4/labels").query("Type", kind))
            .await?
            .labels)
    }

    /// Labels of the given types, concatenated in order.
    pub async fn get_labels_of(&self, kinds: &[i64]) -> Result<Vec<Label>> {
        let mut out = Vec::new();
        for k in kinds {
            out.extend(self.get_labels(*k).await?);
        }
        Ok(out)
    }

    /// Read a single label by listing the relevant types (§8.4).
    pub async fn get_label(&self, id: &str, kinds: &[i64]) -> Result<Label> {
        self.get_labels_of(kinds)
            .await?
            .into_iter()
            .find(|l| l.id == id)
            .ok_or_else(|| Error::NotFound(format!("label {id}")))
    }

    /// `POST /core/v4/labels`.
    pub async fn create_label(
        &self,
        name: &str,
        color: &str,
        kind: i64,
        parent_id: Option<&str>,
    ) -> Result<Label> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Label")]
            label: Label,
        }
        let mut body = json!({ "Name": name, "Color": color, "Type": kind });
        if let Some(p) = parent_id.filter(|p| !p.is_empty()) {
            body["ParentID"] = json!(p);
        }
        Ok(self
            .send_json::<R>(Request::post("/core/v4/labels").json(body))
            .await?
            .label)
    }

    /// `PUT /core/v4/labels/{id}`.
    pub async fn update_label(
        &self,
        id: &str,
        name: &str,
        color: &str,
        parent_id: Option<&str>,
    ) -> Result<Label> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Label")]
            label: Label,
        }
        let mut body = json!({ "Name": name, "Color": color });
        if let Some(p) = parent_id.filter(|p| !p.is_empty()) {
            body["ParentID"] = json!(p);
        }
        Ok(self
            .send_json::<R>(Request::put(format!("/core/v4/labels/{id}")).json(body))
            .await?
            .label)
    }

    /// `DELETE /core/v4/labels/{id}`.
    pub async fn delete_label(&self, id: &str) -> Result<()> {
        self.send(Request::delete(format!("/core/v4/labels/{id}")))
            .await?;
        Ok(())
    }

    /// `GET /core/v4/events/latest` → EventID.
    pub async fn get_latest_event_id(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "EventID")]
            event_id: String,
        }
        Ok(self
            .send_json::<R>(Request::get("/core/v4/events/latest"))
            .await?
            .event_id)
    }

    /// `GET /core/v4/events/{id}` — a single event.
    pub async fn get_event(&self, event_id: &str) -> Result<Event> {
        self.send_json(Request::get(format!("/core/v4/events/{event_id}")))
            .await
    }

    /// Chained fetch (§8.5): follow `More = 1` up to the chain cap. Returns
    /// an empty list when nothing changed.
    pub async fn get_events_chained(&self, event_id: &str) -> Result<Vec<Event>> {
        let mut out = Vec::new();
        let mut cursor = event_id.to_string();
        for _ in 0..limits::EVENT_CHAIN_CAP {
            let ev = self.get_event(&cursor).await?;
            if ev.event_id == cursor {
                break;
            }
            cursor = ev.event_id.clone();
            let more = ev.more;
            out.push(ev);
            if !more {
                break;
            }
        }
        Ok(out)
    }

    /// `GET /core/v4/settings`.
    pub async fn get_user_settings(&self) -> Result<UserSettings> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "UserSettings", default)]
            user_settings: UserSettings,
        }
        Ok(self
            .send_json::<R>(Request::get("/core/v4/settings"))
            .await?
            .user_settings)
    }
}
