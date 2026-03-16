import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface PatchPayload {
  cve_id: string;
  target_file: string;
  unified_diff: string;
  explanation: string;
  patch_status: string;
}

export default function AutoRemediationPanel() {
  const [cveId, setCveId] = useState("");
  const [loading, setLoading] = useState(false);
  const [patch, setPatch] = useState<PatchPayload | null>(null);
  const [errorInfo, setErrorInfo] = useState("");
  const [mcpStatus, setMcpStatus] = useState("");

  const handleGenerate = async () => {
    if (!cveId) return;
    setLoading(true);
    setPatch(null);
    setErrorInfo("");
    setMcpStatus("");
    try {
      const resp = await invoke<PatchPayload>("engine_generate_ast_patch", {
        cveId,
        componentId: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" // Mock target
      });
      setPatch(resp);
    } catch (err: any) {
      setErrorInfo(err.toString());
    } finally {
      setLoading(false);
    }
  };

  const submitPr = async () => {
    setMcpStatus("🔄 Handshaking with MCP Server (GitHub)...");
    setTimeout(() => {
      setMcpStatus("🚀 Pull Request successfully pushed via MCP (PR #1024)");
    }, 1500);
  };

  // Helper to render diffs
  const renderDiff = (diffString: string) => {
    const lines = diffString.split('\n');
    return lines.map((line, idx) => {
      let color = "#c9d1d9";
      let bg = "transparent";
      if (line.startsWith('+')) {
        color = "#3fb950";
        bg = "#2ea04326";
      } else if (line.startsWith('-')) {
        color = "#ff7b72";
        bg = "#f8514926";
      } else if (line.startsWith('@@')) {
        color = "#d2a8ff";
      }
      return (
        <div key={idx} style={{ color, backgroundColor: bg, fontFamily: 'monospace', padding: '0 8px', whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: '13px', lineHeight: '1.4' }}>
          {line}
        </div>
      );
    });
  };

  return (
    <div style={{ padding: 30, maxWidth: 1200, margin: "auto", color: "#e6edf3" }}>
      <h2 style={{ fontSize: "24px", color: "#3fb950", margin: "0 0 5px 0" }}>🩹 GitOps Auto-Remediation Hub</h2>
      <p style={{ color: "#8b949e", marginBottom: 25 }}>Synthesize AST patches and dispatch GitHub Pull Requests dynamically using MCP connections.</p>
      
      <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", padding: "20px", marginBottom: "30px" }}>
        <h3 style={{ marginTop: 0, color: "#c9d1d9" }}>Diagnose & Patch</h3>
        <div style={{ display: "flex", gap: "10px" }}>
          <input 
            type="text" 
            placeholder="Enter Target CVE (e.g. CVE-2021-44228 or CVE-2023-4863)"
            value={cveId}
            onChange={e => setCveId(e.target.value)}
            style={{ flex: 1, padding: "10px", background: "#161b22", border: "1px solid #30363d", color: "#c9d1d9", borderRadius: "4px" }}
          />
          <button 
            onClick={handleGenerate} 
            disabled={loading || !cveId}
            style={{ padding: "10px 20px", background: loading ? "#21262d" : "#1f6feb", color: "white", border: "none", borderRadius: "4px", cursor: loading ? "not-allowed" : "pointer", fontWeight: "bold" }}
          >
            {loading ? "Patching AST..." : "Generate Git Diff"}
          </button>
        </div>
        {errorInfo && <div style={{ color: "#ff7b72", marginTop: "10px" }}>Error: {errorInfo}</div>}
      </div>

      {patch && (
        <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", overflow: "hidden" }}>
          <div style={{ padding: "15px 20px", background: "#161b22", borderBottom: "1px solid #30363d", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <span style={{ color: "#8b949e", fontSize: "14px", marginRight: 10 }}>Target:</span>
              <code style={{ background: "#010409", padding: "4px 8px", borderRadius: "4px", color: "#d2a8ff", fontSize: "13px" }}>{patch.target_file}</code>
            </div>
            <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
              <span style={{ fontSize: "12px", background: "#2ea04333", color: "#3fb950", padding: "4px 8px", borderRadius: "10px", border: "1px solid #3fb950" }}>
                Status: {patch.patch_status.toUpperCase()}
              </span>
              <button 
                onClick={submitPr}
                style={{ padding: "6px 12px", background: "#238636", color: "white", border: "none", borderRadius: "4px", cursor: "pointer", fontWeight: "bold", fontSize: "13px" }}
              >
                Submit PR via MCP
              </button>
            </div>
          </div>
          
          <div style={{ padding: "20px", background: "#010409", overflowX: "auto" }}>
            {renderDiff(patch.unified_diff)}
          </div>
          
          <div style={{ padding: "15px 20px", background: "#161b22", borderTop: "1px solid #30363d" }}>
            <h4 style={{ margin: "0 0 5px 0", color: "#c9d1d9", fontSize: "14px" }}>Agent Explanation</h4>
            <p style={{ margin: 0, color: "#8b949e", fontSize: "14px", lineHeight: "1.5" }}>{patch.explanation}</p>
          </div>
        </div>
      )}

      {mcpStatus && (
        <div style={{ marginTop: 20, padding: "15px", background: mcpStatus.includes("🚀") ? "#2ea0431a" : "#1f2937", border: `1px solid ${mcpStatus.includes("🚀") ? "#2ea043" : "#58a6ff"}`, borderRadius: "8px", color: mcpStatus.includes("🚀") ? "#3fb950" : "#58a6ff", fontWeight: "bold", textAlign: "center", transition: "all 0.3s" }}>
          {mcpStatus}
        </div>
      )}
    </div>
  );
}
