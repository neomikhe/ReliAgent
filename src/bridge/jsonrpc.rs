//! JSON-RPC 2.0 wire types. Minimal subset used by the bridge — just
//! enough to encode single requests and decode single responses. No
//! batching, no notification handling on the response side.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct RpcRequest {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: String,
    pub params: Value,
}

impl RpcRequest {
    pub fn new<P: Serialize>(id: u64, method: &str, params: &P) -> Result<Self, serde_json::Error> {
        Ok(Self {
            jsonrpc: "2.0",
            id,
            method: method.to_string(),
            params: serde_json::to_value(params)?,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct RpcResponse {
    #[allow(dead_code)]
    pub jsonrpc: Option<String>,
    #[allow(dead_code)]
    pub id: Option<Value>,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub data: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serializes_to_canonical_form() {
        let req = RpcRequest::new(1, "ping", &serde_json::json!({})).unwrap();
        let encoded = serde_json::to_string(&req).unwrap();
        assert!(encoded.contains("\"jsonrpc\":\"2.0\""));
        assert!(encoded.contains("\"method\":\"ping\""));
        assert!(encoded.contains("\"id\":1"));
    }

    #[test]
    fn response_with_result_decodes() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"result":{"pong":true}}"#;
        let resp: RpcResponse = serde_json::from_str(raw).unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["pong"], serde_json::json!(true));
    }

    #[test]
    fn response_with_error_decodes() {
        let raw =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}"#;
        let resp: RpcResponse = serde_json::from_str(raw).unwrap();
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "method not found");
    }

    #[test]
    fn response_with_null_id_on_parse_error_decodes() {
        let raw = r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}"#;
        let resp: RpcResponse = serde_json::from_str(raw).unwrap();
        assert!(resp.error.is_some());
    }
}
