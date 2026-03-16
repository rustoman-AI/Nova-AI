use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = "d4ee932b-2f90-406c-ac7a-1c5d379389db";
    let url = "https://api.nova.amazon.com/v1/chat/completions";

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", api_key))?,
    );

    let client = reqwest::Client::new();
    let body = json!({
        "model": "nova-2-lite-v1",
        "messages": [
            {
                "role": "user",
                "content": "Hello, respond with 'Nova is active'"
            }
        ],
        "temperature": 0.7
    });

    println!("Sending ping to Amazon Nova API...");

    let response = client
        .post(url)
        .headers(headers)
        .json(&body)
        .send()
        .await?;

    if response.status().is_success() {
        let res_json: serde_json::Value = response.json().await?;
        let content = res_json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("Empty response")
            .to_string();
        println!("✅ Server response: {}", content);
    } else {
        let error_text = response.text().await?;
        println!("❌ Nova API Error: {}", error_text);
    }

    Ok(())
}
