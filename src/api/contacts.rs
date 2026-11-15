//! Contacts endpoints (§8.12).

use serde::Deserialize;

use super::client::{ApiClient, Request};
use super::types::{Contact, ContactEmail};
use crate::config::limits;
use crate::error::Result;
use crate::util::null_default;

impl ApiClient {
    /// All contact emails matching `email`, paging until `Total` is covered.
    pub async fn get_contact_emails(&self, email: &str) -> Result<Vec<ContactEmail>> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "ContactEmails", default, deserialize_with = "null_default")]
            contact_emails: Vec<ContactEmail>,
            #[serde(rename = "Total", default)]
            total: i64,
        }
        let mut out = Vec::new();
        let mut page = 0usize;
        loop {
            let r: R = self
                .send_json(
                    Request::get("/contacts/v4/emails")
                        .query("Email", email)
                        .query("Page", page)
                        .query("PageSize", limits::LIST_PAGE_SIZE),
                )
                .await?;
            let n = r.contact_emails.len();
            out.extend(r.contact_emails);
            if n == 0 || out.len() as i64 >= r.total {
                return Ok(out);
            }
            page += 1;
        }
    }

    /// `GET /contacts/v4/{id}`.
    pub async fn get_contact(&self, id: &str) -> Result<Contact> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Contact")]
            contact: Contact,
        }
        Ok(self
            .send_json::<R>(Request::get(format!("/contacts/v4/{id}")))
            .await?
            .contact)
    }
}
