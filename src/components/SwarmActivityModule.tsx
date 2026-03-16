import { useState, useEffect } from "react";
import { listen, emit, Event } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import AgentHierarchyGraph from "./AgentHierarchyGraph";
import AgentLoopTracker from "./AgentLoopTracker";

export type SwarmEventPayload = 
  | { type: "Log", agent: string, message: string }
  | { type: "ThreatDetected", node_id: string, vuln_id: string, description: string }
  | { type: "ReviewRequested", node_id: string, vuln_id: string, original_code: string, proposed_patch: string }
  | { type: "ReviewResult", node_id: string, vuln_id: string, approved: boolean, feedback: string, proposed_patch: string }
  | { type: "FilePatched", node_id: string, vuln_id: string, file_path: string }
  | { type: "GitCommitCreated", node_id: string, vuln_id: string, commit_hash: string, branch: string }
  | { type: "ComplianceResult", node_id: string, vuln_id: string, passed: boolean, score: number, details: string }
  | { type: "RollbackPerformed", node_id: string, vuln_id: string, commit_id: string, reason: string }
  | { type: "TeamOrchestration", payload: { source: string, destination: string, summary: string, next_action: string, artifacts: string[], needs: string[] } }
  | { type: "AgentStateChanged", agent_id: string, state: string, details: string };

export default function SwarmActivityModule() {
  const [events, setEvents] = useState<SwarmEventPayload[]>([]);

  useEffect(() => {
    // Listen for swarm events coming from Rust
    const unlisten = listen<SwarmEventPayload>("swarm-event", (event: Event<SwarmEventPayload>) => {
      setEvents((prev) => [...prev, event.payload]);
      
      // Auto-scroll to bottom behavior could be added here
    });

    return () => {
      unlisten.then((f) => f());
    };
  }, []);

  const triggerDemo = async () => {
      // In a real scenario, the rust backend agents would just run. 
      // For this demo view, we'll invoke a command to kick off the threat intel agent
      try {
          await invoke("trigger_swarm_demo");
      } catch(e) {
          console.error("Failed to trigger demo", e);
      }
  };

  const clearLog = () => setEvents([]);

  return (
    <div className="swarm-module-container">
      <div className="swarm-header">
        <h2>⚡ AI Security Swarm Activity</h2>
        <div className="swarm-controls">
           <button onClick={triggerDemo} className="primary-btn">Simulate Threat</button>
           <button onClick={clearLog} className="secondary-btn">Clear Log</button>
        </div>
      </div>
      
      <AgentLoopTracker />

      <div className="swarm-content-layout" style={{ marginTop: '20px' }}>
        <div className="swarm-log">
          {events.length === 0 ? (
            <div className="empty-state">No swarm activity yet. Agents are standing by.</div>
          ) : (
            events.map((ev, i) => (
              <div key={i} className={`swarm-card ${ev.type.toLowerCase()}`}>
                {ev.type === "Log" && (
                  <div className="log-row">
                    <span className="agent-badge">{ev.agent}</span>
                    <span className="log-msg">{ev.message}</span>
                  </div>
                )}
                {ev.type === "ThreatDetected" && (
                  <div className="threat-row">
                    <div className="card-header">
                       <span className="icon">🛑</span> 
                       <strong>
                         THREAT DETECTED:{' '}
                         <span 
                           className="vuln-id-badge clickable-vuln" 
                           onClick={() => emit('open-knowledge-panel', { query: `cve ${ev.vuln_id}` })}
                         >
                           {ev.vuln_id}
                         </span>
                       </strong>
                    </div>
                    <div className="card-body">
                       <p><strong>Node:</strong> <code>{ev.node_id}</code></p>
                       <p>{ev.description}</p>
                    </div>
                  </div>
                )}
                {ev.type === "ReviewRequested" && (
                  <div className="review-req-row">
                     <div className="card-header">
                       <span className="icon">⚖️</span> 
                       <strong>PATCH GENERATED</strong>
                    </div>
                    <div className="card-body">
                        <p>PatchAgent generated proposed fix for <code>{ev.node_id}</code>. Sending to NovaShield for review...</p>
                    </div>
                  </div>
                )}
                {ev.type === "ReviewResult" && (
                  <div className={`review-res-row ${ev.approved ? "approved" : "rejected"}`}>
                    <div className="card-header">
                       <span className="icon">{ev.approved ? "✅" : "❌"}</span> 
                       <strong>REVIEW {ev.approved ? "APPROVED" : "REJECTED"}</strong>
                    </div>
                    <div className="card-body">
                       <p><strong>Target:</strong> <code>{ev.node_id}</code></p>
                       <div className="feedback-box">
                           <pre>{ev.feedback}</pre>
                       </div>
                    </div>
                  </div>
                )}
                {ev.type === "FilePatched" && (
                  <div className="patch-applied-row" style={{borderColor: '#177ddc', background: 'rgba(23, 125, 220, 0.1)'}}>
                    <div className="card-header" style={{color: '#177ddc'}}>
                       <span className="icon">📝</span> 
                       <strong>PATCH APPLIED LOCALLY</strong>
                    </div>
                    <div className="card-body">
                       <p><strong>File:</strong> <code>{ev.file_path}</code></p>
                    </div>
                    {/* Inline Git Diff Viewer */}
                    <div className="diff-viewer">
                       <div className="diff-header">📝 File Changes</div>
                       <div className="diff-line diff-removed">- let cmd = format!("curl -X POST ... -d 'id={}'", user_input_id);</div>
                       <div className="diff-line diff-added">+ let query = "SELECT * FROM users WHERE id = $1";</div>
                       <div className="diff-line diff-added">+ // Safely execute `query` using sqlx with `user_id` bound as a parameter</div>
                    </div>
                  </div>
                )}
                {ev.type === "GitCommitCreated" && (
                  <div className="patch-applied-row">
                    <div className="card-header">
                       <span className="icon">💾</span> 
                       <strong>PATCH COMMITTED TO GIT</strong>
                    </div>
                    <div className="card-body">
                       <p><strong>Commit:</strong> <code>{ev.commit_hash.substring(0, 8)}</code></p>
                       <p><strong>Branch:</strong> <code>{ev.branch}</code></p>
                       <p style={{color: '#52c41a', fontWeight: 600, marginTop: 8}}>✅ Self-Healing cycle complete.</p>
                    </div>
                  </div>
                )}
                {ev.type === "ComplianceResult" && (
                  <div className={`compliance-row ${ev.passed ? 'passed' : 'failed'}`}>
                    <div className="card-header">
                       <span className="icon">{ev.passed ? '🛡️' : '⚠️'}</span> 
                       <strong>COMPLIANCE AUDIT: {ev.passed ? 'PASSED' : 'FAILED'} ({ev.score}%)</strong>
                    </div>
                    <div className="card-body">
                       <p><strong>Target:</strong> <code>{ev.node_id}</code></p>
                       <div className="feedback-box">
                           <pre>{ev.details}</pre>
                       </div>
                    </div>
                  </div>
                )}
                {ev.type === "RollbackPerformed" && (
                  <div className="rollback-row">
                    <div className="card-header">
                       <span className="icon">⏪</span> 
                       <strong>AUTO-ROLLBACK PERFORMED</strong>
                    </div>
                    <div className="card-body">
                       <p><strong>Reverted commit:</strong> <code>{ev.commit_id.substring(0, 8)}</code></p>
                       <p><strong>Reason:</strong> {ev.reason}</p>
                    </div>
                  </div>
                )}
                {ev.type === "TeamOrchestration" && (
                  <div className="team-orchestration-row">
                    <div className="card-header">
                       <span className="icon">📡</span> 
                       <strong>IPC MESSAGE: {ev.payload.source} ➔ {ev.payload.destination}</strong>
                    </div>
                    <div className="card-body">
                       <p><strong>Summary:</strong> {ev.payload.summary}</p>
                       <p><strong>Next Action:</strong> {ev.payload.next_action}</p>
                       {ev.payload.artifacts.length > 0 && <p><strong>Artifacts:</strong> {ev.payload.artifacts.join(", ")}</p>}
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
        
        <div className="swarm-hierarchy">
           <h3 className="hierarchy-title">Live Agent Hierarchy & IPC Bus</h3>
           <div className="hierarchy-graph-wrapper">
              <AgentHierarchyGraph />
           </div>
        </div>
      </div>

      <style>{`
        .swarm-module-container {
          padding: 20px;
          height: 100%;
          display: flex;
          flex-direction: column;
          background: #0a0a16;
          color: #e0e0e0;
        }
        .swarm-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
          padding-bottom: 10px;
          border-bottom: 1px solid #1a1a30;
        }
        .swarm-header h2 {
           margin: 0;
           font-size: 1.5rem;
           background: -webkit-linear-gradient(#4facfe, #00f2fe);
           -webkit-background-clip: text;
           -webkit-text-fill-color: transparent;
        }
        .swarm-controls {
           display: flex;
           gap: 10px;
        }
        .primary-btn {
           background: #eb2f96;
           color: white;
           border: none;
           padding: 8px 16px;
           border-radius: 6px;
           cursor: pointer;
           font-weight: 600;
        }
        .secondary-btn {
           background: transparent;
           color: #8c8c8c;
           border: 1px solid #2a2a4a;
           padding: 8px 16px;
           border-radius: 6px;
           cursor: pointer;
        }
        .swarm-content-layout {
            display: grid;
            grid-template-columns: minmax(400px, 1fr) 1fr;
            gap: 20px;
            flex: 1;
            min-height: 0;
            overflow: hidden;
        }
        .swarm-log {
          overflow-y: auto;
          display: flex;
          flex-direction: column;
          gap: 12px;
          padding-right: 10px;
        }
        .swarm-hierarchy {
            background: #0d1117;
            border-radius: 8px;
            border: 1px solid #21262d;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
        }
        .hierarchy-title {
            margin: 0;
            padding: 12px 16px;
            background: #161b22;
            border-bottom: 1px solid #21262d;
            font-size: 0.85rem;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            display: flex;
            align-items: center;
        }
        .hierarchy-title::before {
            content: "👥";
            margin-right: 8px;
            font-size: 1.1rem;
        }
        .hierarchy-graph-wrapper {
            flex: 1;
            position: relative;
        }
        .empty-state {
           text-align: center;
           color: #555;
           margin-top: 40px;
           font-style: italic;
        }
        .swarm-card {
           background: #121222;
           border-radius: 8px;
           padding: 12px;
           border-left: 4px solid #333;
           animation: slideIn 0.3s ease-out;
        }
        @keyframes slideIn {
           from { opacity: 0; transform: translateY(10px); }
           to { opacity: 1; transform: translateY(0); }
        }
        
        .swarm-card.log { border-left-color: #4facfe; }
        .log-row { display: flex; align-items: flex-start; gap: 10px; }
        .agent-badge { 
           background: #1a1a30; 
           padding: 2px 8px; 
           border-radius: 12px; 
           font-size: 0.75rem; 
           color: #a0a0ff;
           font-weight: bold;
           white-space: nowrap;
        }
        .log-msg { font-size: 0.9rem; color: #ccc; }

        .swarm-card.threatdetected { border-left-color: #ff4d4f; background: rgba(255, 77, 79, 0.05); }
        .swarm-card.reviewrequested { border-left-color: #faad14; background: rgba(250, 173, 20, 0.05); }
        .review-res-row.approved { border-left: 4px solid #52c41a; background: rgba(82, 196, 26, 0.08); }
        .review-res-row.approved .card-header { color: #52c41a; }
        .review-res-row.approved .feedback-box { border-color: #52c41a33; }
        .review-res-row.approved .feedback-box pre { color: #95de64; }
        .review-res-row.rejected { border-left: 4px solid #ff4d4f; background: rgba(255, 77, 79, 0.08); }
        .review-res-row.rejected .card-header { color: #ff4d4f; }
        .review-res-row.rejected .feedback-box { border-color: #ff4d4f33; }
        .review-res-row.rejected .feedback-box pre { color: #ff7875; }
        .swarm-card.patchapplied { border-left-color: #52c41a; background: rgba(82, 196, 26, 0.1); }
        .patch-applied-row { border-left: 4px solid #52c41a; background: rgba(82, 196, 26, 0.1); padding: 12px; border-radius: 8px; }
        .patch-applied-row .card-header { color: #52c41a; }
        .diff-viewer { background: #000; border: 1px solid #21262d; border-radius: 6px; margin-top: 10px; padding: 10px; font-family: monospace; font-size: 0.82rem; overflow-x: auto; }
        .diff-header { color: #8b949e; font-weight: 600; margin-bottom: 6px; font-size: 0.85rem; }
        .diff-line { padding: 2px 6px; border-radius: 3px; white-space: pre; }
        .diff-removed { background: rgba(255, 77, 79, 0.12); color: #ff7875; }
        .diff-added { background: rgba(82, 196, 26, 0.12); color: #95de64; }
        .compliance-row { padding: 12px; border-radius: 8px; }
        .compliance-row.passed { border-left: 4px solid #722ed1; background: rgba(114, 46, 209, 0.08); }
        .compliance-row.passed .card-header { color: #b37feb; }
        .compliance-row.passed .feedback-box pre { color: #d3adf7; }
        .compliance-row.failed { border-left: 4px solid #faad14; background: rgba(250, 173, 20, 0.08); }
        .compliance-row.failed .card-header { color: #faad14; }
        .rollback-row { border-left: 4px solid #fa8c16; background: rgba(250, 140, 22, 0.08); padding: 12px; border-radius: 8px; }
        .rollback-row .card-header { color: #fa8c16; }
        
        .team-orchestration-row { border-left: 4px solid #13c2c2; background: rgba(19, 194, 194, 0.08); padding: 12px; border-radius: 8px; }
        .team-orchestration-row .card-header { color: #5cdbd3; font-weight: bold; }
        
        .card-header {
           display: flex;
           align-items: center;
           gap: 8px;
           margin-bottom: 8px;
           font-size: 1rem;
        }
        .card-body p {
           margin: 4px 0;
           font-size: 0.9rem;
           color: #d9d9d9;
        }
        code {
           background: #1a1a30;
           padding: 2px 4px;
           border-radius: 4px;
           color: #52c41a;
           font-family: monospace;
        }
        .feedback-box {
           background: #000;
           padding: 10px;
           border-radius: 6px;
           margin-top: 8px;
           overflow-x: auto;
           border: 1px solid #1a1a30;
        }
        .feedback-box pre {
           margin: 0;
           font-size: 0.85rem;
           color: #ff7875;
           white-space: pre-wrap;
        }
      `}</style>
    </div>
  );
}
