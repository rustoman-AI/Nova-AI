import { useState, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface WasmExecutionResult {
  policy_name: string;
  evaluation_time_ms: number;
  verdict: string;
  console_output: string[];
}

export default function WasmPluginsPanel() {
  const [pluginFile, setPluginFile] = useState<File | null>(null);
  const [targetContext, setTargetContext] = useState("pkg:npm/react@18.2.0");
  const [executing, setExecuting] = useState(false);
  const [result, setResult] = useState<WasmExecutionResult | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const consoleRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [logs]);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setPluginFile(e.target.files[0]);
    }
  };

  const executePlugin = async () => {
    if (!pluginFile || !targetContext) return;
    
    setExecuting(true);
    setResult(null);
    setLogs(["[SYSTEM] Allocating zero-trust V8 memory isolate...", `[SYSTEM] Uploading virtual binary: ${pluginFile.name}...`]);
    
    try {
      // Simulate live streaming by delaying the Tauri call slightly
      setTimeout(async () => {
        try {
          const res = await invoke<WasmExecutionResult>("engine_execute_wasm_policy", {
            pluginName: pluginFile.name,
            targetNode: targetContext
          });
          
          // Stream logs purely for visual effect in the dashboard
          let currentLogIdx = 0;
          const streamInterval = setInterval(() => {
            if (currentLogIdx < res.console_output.length) {
              setLogs(prev => [...prev, res.console_output[currentLogIdx]]);
              currentLogIdx++;
            } else {
              clearInterval(streamInterval);
              setResult(res);
              setExecuting(false);
            }
          }, 150);
        } catch (err: any) {
          setLogs(prev => [...prev, `[ERROR] Host execution aborted: ${err.toString()}`]);
          setExecuting(false);
        }
      }, 500);

    } catch (err: any) {
      setLogs(prev => [...prev, `[FATAL] Sandbox initialization failed: ${err.toString()}`]);
      setExecuting(false);
    }
  };

  return (
    <div style={{ padding: 30, maxWidth: 1200, margin: "auto", color: "#e6edf3" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
        <div>
          <h2 style={{ fontSize: "24px", color: "#58a6ff", margin: "0 0 5px 0" }}>⚡ Zero-Trust Policy Engine</h2>
          <p style={{ color: "#8b949e", margin: 0 }}>Execute isolated WebAssembly security policies against the graph environment.</p>
        </div>
        {result && (
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: "12px", color: "#8b949e", marginBottom: 5 }}>Execution Verdict</div>
            <div style={{ 
              background: result.verdict === "PASS" ? "#2ea0431a" : "#f851491a", 
              color: result.verdict === "PASS" ? "#3fb950" : "#ff7b72",
              border: `1px solid ${result.verdict === "PASS" ? "#2ea043" : "#f85149"}`,
              padding: "10px 20px", borderRadius: "8px", fontWeight: "bold", fontSize: "20px", display: "inline-block"
            }}>
              {result.verdict}
            </div>
            <div style={{ fontSize: "11px", color: "#8b949e", marginTop: 5 }}>Runtime: {result.evaluation_time_ms}ms</div>
          </div>
        )}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginBottom: "20px" }}>
        {/* Upload Pane */}
        <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", padding: "20px" }}>
          <h3 style={{ margin: "0 0 15px 0", color: "#c9d1d9", fontSize: "16px" }}>1. Load Policy Binary</h3>
          <div style={{ border: "2px dashed #444c56", borderRadius: "6px", padding: "30px", textAlign: "center", background: "#161b22", cursor: "pointer", position: "relative" }}>
            <input 
              type="file" 
              accept=".wasm" 
              onChange={handleFileUpload}
              style={{ position: "absolute", top: 0, left: 0, width: "100%", height: "100%", opacity: 0, cursor: "pointer" }}
            />
            {pluginFile ? (
              <div>
                <div style={{ fontSize: "24px", marginBottom: "10px" }}>📦</div>
                <div style={{ color: "#3fb950", fontWeight: "bold" }}>{pluginFile.name}</div>
                <div style={{ color: "#8b949e", fontSize: "12px", marginTop: "5px" }}>{(pluginFile.size / 1024).toFixed(2)} KB</div>
              </div>
            ) : (
              <div>
                <div style={{ fontSize: "24px", marginBottom: "10px" }}>📥</div>
                <div style={{ color: "#58a6ff" }}>Click or Drag a .wasm file</div>
                <div style={{ color: "#8b949e", fontSize: "12px", marginTop: "5px" }}>Custom Rust, Rego, or Go compliance rules</div>
              </div>
            )}
          </div>
        </div>

        {/* Target Context Pane */}
        <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", padding: "20px", display: "flex", flexDirection: "column" }}>
          <h3 style={{ margin: "0 0 15px 0", color: "#c9d1d9", fontSize: "16px" }}>2. Graph Evaluation Context</h3>
          <label style={{ fontSize: "12px", color: "#8b949e", marginBottom: "8px" }}>Target SBOM Node / PurL</label>
          <input 
            type="text" 
            value={targetContext}
            onChange={(e) => setTargetContext(e.target.value)}
            placeholder="e.g. pkg:maven/log4j/log4j-core@2.14.1"
            style={{ padding: "12px", background: "#161b22", border: "1px solid #30363d", color: "#c9d1d9", borderRadius: "6px", fontFamily: "monospace", width: "100%", boxSizing: "border-box" }}
          />
          <div style={{ flex: 1 }}></div>
          <button 
            onClick={executePlugin}
            disabled={!pluginFile || executing || !targetContext}
            style={{ 
              width: "100%", padding: "12px", 
              background: (!pluginFile || executing || !targetContext) ? "#21262d" : "#v238636", 
              backgroundColor: (!pluginFile || executing || !targetContext) ? "#21262d" : "#238636", 
              color: "white", border: "none", borderRadius: "6px", 
              cursor: (!pluginFile || executing || !targetContext) ? "not-allowed" : "pointer", 
              fontWeight: "bold", fontSize: "14px", transition: "all 0.2s" 
            }}
          >
            {executing ? "Running Isolated Sandbox..." : "Execute Policy Engine"}
          </button>
        </div>
      </div>

      {/* Execution Terminal */}
      <div style={{ background: "#010409", border: "1px solid #30363d", borderRadius: "8px", overflow: "hidden" }}>
        <div style={{ background: "#161b22", borderBottom: "1px solid #30363d", padding: "10px 15px", display: "flex", alignItems: "center" }}>
          <div style={{ display: "flex", gap: "6px", marginRight: "15px" }}>
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#ff5f56" }}></div>
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#ffbd2e" }}></div>
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#27c93f" }}></div>
          </div>
          <span style={{ color: "#8b949e", fontSize: "12px", fontFamily: "monospace" }}>tty: wasm-sandbox-output</span>
        </div>
        <div ref={consoleRef} style={{ height: "300px", padding: "15px", overflowY: "auto", fontFamily: "monospace", fontSize: "13px", lineHeight: "1.6" }}>
          {logs.length === 0 ? (
            <div style={{ color: "#6e7681", fontStyle: "italic" }}>Waiting for policy execution...</div>
          ) : (
            logs.map((log, idx) => {
              let color = "#c9d1d9";
              if (log.includes("[ERROR]") || log.includes("[FATAL]") || log.includes("DENY")) color = "#ff7b72";
              if (log.includes("ALLOW") || log.includes("[SUCCESS]")) color = "#3fb950";
              if (log.includes("[WASM-CORE]")) color = "#58a6ff";
              if (log.includes("[WASM-GUEST]")) color = "#d2a8ff";

              return (
                <div key={idx} style={{ color }}>
                  <span style={{ color: "#6e7681", marginRight: 10 }}>
                    {new Date().toISOString().split('T')[1].slice(0, 12)}
                  </span>
                  {log}
                </div>
              );
            })
          )}
          {executing && (
            <div style={{ color: "#58a6ff", marginTop: "10px", animation: "pulse 1.5s infinite" }}>
              █
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
