use crate::PassClient;
use anyhow::{Context, Result};
use pass_domain::{
    ItemContent, ItemData, ItemExtraField, ItemExtraFieldContent, ItemId, ShareId, SshKeyItem,
};

#[derive(Clone, Debug)]
pub struct SshKeyItemCreatePayload {
    pub title: String,
    pub private_key: String,
    pub public_key: String,
    pub passphrase: Option<String>,
}

impl PassClient {
    pub async fn create_ssh_key(
        &self,
        share_id: &ShareId,
        payload: SshKeyItemCreatePayload,
    ) -> Result<ItemId> {
        let mut extra_fields = vec![];

        // If passphrase is provided, add it as a hidden field
        if let Some(passphrase) = payload.passphrase {
            extra_fields.push(ItemExtraField {
                name: "Passphrase".to_string(),
                content: ItemExtraFieldContent::Hidden(passphrase),
            });
        }

        let content = ItemData {
            title: payload.title.to_string(),
            note: String::new(),
            item_uuid: ItemData::generate_uuid(),
            content: ItemContent::SshKey(SshKeyItem {
                private_key: payload.private_key,
                public_key: payload.public_key,
            }),
            extra_fields,
        };

        let req = self
            .create_item_request_from_data(share_id, content)
            .await
            .context("Error creating item request")?;

        self.send_create_item_request(share_id, req)
            .await
            .context("Error sending create item request")
    }
}
