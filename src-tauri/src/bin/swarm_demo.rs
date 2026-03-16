use std::sync::Arc;
use cyclonedx_tauri_ui_lib::actor_registry::{SwarmBus, SwarmEvent};
use cyclonedx_tauri_ui_lib::agents::threat_intel::ThreatIntelAgent;
use cyclonedx_tauri_ui_lib::agents::patch_agent::PatchAgent;
use cyclonedx_tauri_ui_lib::agents::reviewer_agent::ReviewerAgent;
use cyclonedx_tauri_ui_lib::agents::fuzz_agent::FuzzAgent;
use dotenvy::dotenv;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    dotenv().ok();
    
    println!("=======================================================");
    println!("🚀 INITIALIZING MULTI-AGENT SWARM");
    println!("=======================================================\n");

    let bus = SwarmBus::new();
    let mut rx = bus.subscribe();

    let threat_intel = ThreatIntelAgent::new(Arc::clone(&bus));
    // let patch_agent = PatchAgent::new(Arc::clone(&bus));
    let reviewer_agent = ReviewerAgent::new(Arc::clone(&bus));
    let fuzz_agent = FuzzAgent::new(Arc::clone(&bus));

    // Spawn the central event logger
    tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            match event {
                SwarmEvent::Log { agent, message } => {
                     println!("[{:>15}] {}", agent, message);
                }
                SwarmEvent::ThreatDetected { node_id, description, .. } => {
                     println!("\n╭───────────────────────────────────────────────────╮");
                     println!("│ 🛑 EVENT: THREAT DETECTED                          │");
                     println!("│ -> Node: {:<40} │", node_id);
                     println!("│ -> Desc: {:<40} │", description.chars().take(40).collect::<String>());
                     println!("╰───────────────────────────────────────────────────╯\n");
                }
                SwarmEvent::ReviewRequested { node_id, .. } => {
                     println!("\n╭───────────────────────────────────────────────────╮");
                     println!("│ ⚖️ EVENT: REVIEW REQUESTED                         │");
                     println!("│ -> Patch generated for: {:<25} │", node_id);
                     println!("╰───────────────────────────────────────────────────╯\n");
                }
                SwarmEvent::ReviewResult { node_id, approved, feedback, .. } => {
                     let status = if approved { "APPROVED ✅" } else { "REJECTED ❌" };
                     println!("\n╭───────────────────────────────────────────────────╮");
                     println!("│ 🛡️ EVENT: REVIEW RESULT                            │");
                     println!("│ -> Node:    {:<38} │", node_id);
                     println!("│ -> Status:  {:<38} │", status);
                     println!("│ -> Details: {:<38} │", feedback.chars().take(38).collect::<String>());
                     println!("╰───────────────────────────────────────────────────╯\n");
                }
                SwarmEvent::FilePatched { node_id, file_path, .. } => {
                     println!("\n💾 PATCH APPLIED: {} -> {}", file_path, node_id);
                }
                SwarmEvent::ComplianceResult { score, passed, .. } => {
                     println!("\n🛡️ COMPLIANCE: {} ({}%)", if passed { "PASSED" } else { "FAILED" }, score);
                }
                SwarmEvent::RollbackPerformed { commit_id, reason, .. } => {
                     let short = if commit_id.len() >= 8 { &commit_id[..8] } else { &commit_id };
                     println!("\n⏪ ROLLBACK: {} — {}", short, reason);
                }
                SwarmEvent::TestPassed { node_id, test_type, passed, details, .. } => {
                     println!("\n🧪 TEST {}: {} ({}) — {}", if passed { "PASSED" } else { "FAILED" }, node_id, test_type, details);
                }
                SwarmEvent::FuzzResult { node_id, mutations, crashes, coverage_pct, .. } => {
                     println!("\n🔀 FUZZ: {} — {} mutations, {} crashes, {:.1}% coverage", node_id, mutations, crashes, coverage_pct);
                }
                SwarmEvent::ExploitChainDetected { chain_id, stages, severity, .. } => {
                     println!("\n⛓️ EXPLOIT CHAIN {}: {} ({} stages)", chain_id, severity, stages.len());
                }
                SwarmEvent::TestFailed { node_id, test_type, error, .. } => {
                     println!("\n❌ TEST FAILED: {} ({}) — {}", node_id, test_type, error);
                }
                SwarmEvent::DependencyRisk { package, risk_level, description, .. } => {
                     println!("\n🔗 DEP RISK: {} [{}] — {}", package, risk_level, description);
                }
                SwarmEvent::PolicyViolation { framework, rule, severity, .. } => {
                     println!("\n⚠️ POLICY VIOLATION: {} [{}] — {}", framework, severity, rule);
                }
                SwarmEvent::ExploitSimulation { phase, attacker_action, defender_response, success, severity_score, .. } => {
                     let icon = if success { "🔴" } else { "🔵" };
                     println!("\n{} SIM [{}] (severity {:.1})", icon, phase, severity_score);
                     println!("   ATK: {}", attacker_action);
                     println!("   DEF: {}", defender_response);
                }
                SwarmEvent::TeamOrchestration { payload } => {
                     let msg = payload.payload;
                     println!("\n╭───────────────────────────────────────────────────╮");
                     println!("│ 📡 IPC: {} ➔ {} │", msg.source, msg.destination);
                     println!("│ -> Summary: {:<38} │", msg.summary.chars().take(38).collect::<String>());
                     println!("│ -> Action:  {:<38} │", msg.next_action.chars().take(38).collect::<String>());
                     println!("╰───────────────────────────────────────────────────╯\n");
                }
                _ => {}
            }
        }
    });

    // Spawn the agents
    // tokio::spawn(async move { patch_agent.run().await; });
    tokio::spawn(async move { reviewer_agent.run().await; });
    tokio::spawn(async move { fuzz_agent.run().await; });

    // Wait for them to spin up
    sleep(std::time::Duration::from_millis(500)).await;

    // Start the threat trigger
    threat_intel.run().await;

    // Let the async cascade finish
    sleep(std::time::Duration::from_secs(10)).await;
    
    println!("\n=======================================================");
    println!("🛑 SWARM SHUTDOWN");
    println!("=======================================================");
}
