use crate::JsonSchema;
use crate::TS;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct WorkerPolicyReadParams {
    pub thread_id: String,
    pub challenge: String,
    /// Construct the native executable registry without starting a model turn.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub prepare: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct WorkerPolicyReadResponse {
    pub attestation: serde_json::Value,
}
