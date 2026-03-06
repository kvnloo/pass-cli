#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PersonalAccessTokenId(pub(crate) String);
display_for_basic!(PersonalAccessTokenId);

impl PersonalAccessTokenId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}
