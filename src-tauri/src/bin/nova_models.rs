use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = "d4ee932b-2f90-406c-ac7a-1c5d379389db";
    let url = "https://api.nova.amazon.com/v1/models";

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", api_key))?,
    );

    let client = reqwest::Client::new();
    println!("Fetching available models...");

    let response = client
        .get(url)
        .headers(headers)
        .send()
        .await?;

    if response.status().is_success() {
        let text = response.text().await?;
        println!("Available models: {}", text);
    } else {
        let error_text = response.text().await?;
        println!("❌ API Error: {}", error_text);
    }

    Ok(())
}
