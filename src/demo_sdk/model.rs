use std::sync::Arc;

use crate::AuthorizationContext;

use super::SdkError;

#[derive(Debug)]
pub(crate) struct ModelStore {
    authorization: Arc<AuthorizationContext>,
}

impl ModelStore {
    pub(crate) fn new(authorization: Arc<AuthorizationContext>) -> Self {
        Self { authorization }
    }

    pub(crate) fn require_model(&self, model_id: &str) -> Result<(), SdkError> {
        if self
            .authorization
            .get_resource_scope("model_ids")
            .iter()
            .any(|allowed| allowed == model_id)
        {
            Ok(())
        } else {
            Err(SdkError::ResourceDenied {
                kind: "model",
                id: model_id.to_owned(),
            })
        }
    }
}
