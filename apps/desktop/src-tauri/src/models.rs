//! Model metadata uses native credentials and fixed provider endpoints, never chat content.
use crate::{
    connections::{Provider, key},
    vault::VaultSession,
};
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;

#[derive(Debug, Serialize)]
pub(crate) struct ChatModel {
    pub id: String,
    pub name: String,
    pub is_default: bool,
}

#[tauri::command]
pub(crate) async fn list_chat_models(
    connection_id: String,
    vault: tauri::State<'_, VaultSession>,
    codex: tauri::State<'_, crate::codex_chat::CodexState>,
) -> Result<Vec<ChatModel>, String> {
    if connection_id == "chatgpt" {
        return crate::codex_chat::models(&codex).await;
    }
    let provider = match connection_id.as_str() {
        "openai" => Provider::Openai,
        "anthropic" => Provider::Anthropic,
        _ => return Err("Unknown connection.".into()),
    };
    let credential = key(&vault, provider)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|_| "Could not prepare the model list request.")?;
    let mut request = client.get(match provider {
        Provider::Openai => "https://api.openai.com/v1/models",
        Provider::Anthropic => "https://api.anthropic.com/v1/models?limit=1000",
    });
    request = match provider {
        Provider::Openai => request.header(
            "authorization",
            crate::credentials::sensitive_header(
                format!("Bearer {}", credential.as_str()).as_bytes(),
            )?,
        ),
        Provider::Anthropic => request
            .header(
                "x-api-key",
                crate::credentials::sensitive_header(credential.as_bytes())?,
            )
            .header("anthropic-version", "2023-06-01"),
    };
    let response = request
        .send()
        .await
        .map_err(|_| "Could not load models. Check your connection and retry.")?;
    if !response.status().is_success() {
        return Err(match response.status().as_u16() {
            401 | 403 => "The provider rejected this key. Reconnect it in Connections.",
            429 => "The provider is rate limiting model discovery. Try again shortly.",
            _ => "The provider could not list models. Try again shortly.",
        }
        .into());
    }
    let data: Value = response
        .json()
        .await
        .map_err(|_| "The provider returned an invalid model list.")?;
    parse_models(provider, &data)
}
fn parse_models(provider: Provider, value: &Value) -> Result<Vec<ChatModel>, String> {
    let mut items = value["data"]
        .as_array()
        .ok_or("The provider returned an invalid model list.")?
        .clone();
    items.sort_by_key(|v| std::cmp::Reverse(v["created"].as_u64().unwrap_or(0)));
    let mut result = vec![];
    for item in items {
        let Some(id) = item["id"].as_str() else {
            continue;
        };
        if provider == Provider::Openai
            && (!(id.starts_with("gpt-")
                || id.starts_with("o1")
                || id.starts_with("o3")
                || id.starts_with("o4"))
                || [
                    "audio",
                    "realtime",
                    "transcribe",
                    "tts",
                    "image",
                    "search",
                    "deep-research",
                    "instruct",
                ]
                .iter()
                .any(|s| id.contains(s)))
        {
            continue;
        }
        result.push(ChatModel {
            id: id.into(),
            name: item["display_name"].as_str().unwrap_or(id).into(),
            is_default: false,
        });
    }
    if let Some(first) = result.first_mut() {
        first.is_default = true;
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filters_non_chat_models_and_selects_one_default() {
        let models = parse_models(Provider::Openai, &serde_json::json!({"data":[{"id":"gpt-text","created":1},{"id":"gpt-realtime","created":10},{"id":"text-embedding","created":20},{"id":"gpt-new","created":2}]})).unwrap();
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id, "gpt-new");
        assert!(models[0].is_default);
        assert!(!models[1].is_default);
    }
}
