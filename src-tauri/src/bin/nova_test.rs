use cyclonedx_tauri_ui_lib::nova_client::{NovaClient, ScanRequest};
use dotenvy::dotenv;

#[tokio::main]
async fn main() {
    dotenv().ok(); // Load .env
    
    println!("Testing Nova Shield Bedrock Integration...");
    println!("API Key provided: {}", std::env::var("NOVA_API_KEY").unwrap_or_else(|_| "NOT_SET".to_string()));
    
    // AWS SDK behavior:
    // It looks for AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.
    // We will initialize the client and try a mock scan.
    let result: anyhow::Result<NovaClient> = NovaClient::new().await;
    match result {
        Ok(client) => {
            println!("NovaClient initialized successfully. Sending test payload...");
            
            let req = ScanRequest {
                intent: "terminal_command".to_string(),
                payload: "rm -rf /".to_string(), // High risk payload
            };
            
            let scan_result: anyhow::Result<_> = client.scan(req).await;
            match scan_result {
                Ok(response) => {
                    println!("\n✅ SUCCESS: Nova Shield Responded!");
                    println!("Risk Level: {}", response.risk);
                    println!("Analysis:\n{}", response.analysis);
                }
                Err(e) => {
                    println!("\n❌ FAILED: API call returned an error.");
                    println!("Error Details: {:?}", e);
                    println!("\nNote: AWS Bedrock requires SigV4 credentials (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY). If `NOVA_API_KEY` is a proxy key, we might need to change the endpoint or client.");
                }
            }
        }
        Err(e) => {
            println!("❌ FAILED to initialize NovaClient: {:?}", e);
        }
    }
}
