import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface MCPTool {
  name: string;
  description: string;
  payload_schema: string;
}

interface MCPServer {
  id: string;
  name: string;
  url: string;
  transport: string;
  status: string;
  version: string;
  tools: MCPTool[];
}

export default function MCPServerHub() {
  const [servers, setServers] = useState<MCPServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState(false);
  const [newUrl, setNewUrl] = useState("");
  const [activeServer, setActiveServer] = useState<MCPServer | null>(null);

  useEffect(() => {
    fetchServers();
  }, []);

  const fetchServers = async () => {
    try {
      const resp = await invoke<MCPServer[]>("engine_get_mcp_servers");
      setServers(resp);
      if (resp.length > 0) setActiveServer(resp[0]);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUrl) return;
    setConnecting(true);
    try {
      const newServer = await invoke<MCPServer>("engine_connect_mcp_server", { url: newUrl });
      setServers(prev => [...prev, newServer]);
      setNewUrl("");
      setActiveServer(newServer);
    } catch (err) {
      alert("Failed to connect to MCP Server: " + err);
    } finally {
      setConnecting(false);
    }
  };

  if (loading) return <div style={{ color: "#8b949e", padding: 40 }}>Initializing MCP Registration Hub...</div>;

  return (
    <div style={{ padding: "30px", maxWidth: 1400, margin: "auto", color: "#e6edf3", display: "grid", gridTemplateColumns: "350px 1fr", gap: "30px" }}>
      {/* LEFT COLUMN: SERVER LIST & CONNECT */}
      <div>
        <h2 style={{ fontSize: "24px", color: "#1890ff", margin: "0 0 5px 0" }}>🔌 MCP Servers</h2>
        <p style={{ color: "#8b949e", marginBottom: 20 }}>Model Context Protocol Integration</p>
        
        <form onSubmit={handleConnect} style={{ background: "#0d1117", border: "1px solid #30363d", padding: "15px", borderRadius: "8px", marginBottom: "20px" }}>
          <h4 style={{ margin: "0 0 10px 0", color: "#c9d1d9" }}>Register External Hub</h4>
          <input
            type="text"
            placeholder="MCP Server URI (e.g. wss://...)"
            value={newUrl}
            onChange={(e) => setNewUrl(e.target.value)}
            style={{ width: "100%", padding: "10px", background: "#161b22", border: "1px solid #30363d", color: "white", borderRadius: "4px", marginBottom: "10px", boxSizing: "border-box" }}
          />
          <button 
            type="submit"
            disabled={connecting || !newUrl}
            style={{ width: "100%", padding: "10px", background: connecting ? "#555" : "#238636", color: "white", border: "none", borderRadius: "4px", cursor: connecting ? "not-allowed" : "pointer", fontWeight: "bold" }}
          >
            {connecting ? "Handshaking..." : "Connect MCP"}
          </button>
        </form>

        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          {servers.map((srv) => (
            <div 
              key={srv.id} 
              onClick={() => setActiveServer(srv)}
              style={{
                background: activeServer?.id === srv.id ? "#1f2937" : "#0d1117",
                border: `1px solid ${activeServer?.id === srv.id ? "#58a6ff" : "#30363d"}`,
                padding: "15px",
                borderRadius: "8px",
                cursor: "pointer",
                transition: "all 0.2s"
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 5 }}>
                <strong style={{ color: "#c9d1d9" }}>{srv.name}</strong>
                <span style={{ 
                  fontSize: "10px", padding: "2px 6px", borderRadius: "10px",
                  background: srv.status === "Connected" ? "#2ea04333" : "#f8514933",
                  color: srv.status === "Connected" ? "#3fb950" : "#ff7b72", border: `1px solid ${srv.status === "Connected" ? "#3fb950" : "#ff7b72"}`
                }}>
                  {srv.status.toUpperCase()}
                </span>
              </div>
              <div style={{ fontSize: "12px", color: "#8b949e", fontFamily: "monospace" }}>{srv.transport}://{srv.url}</div>
              <div style={{ fontSize: "12px", color: "#8b949e", marginTop: 5 }}>Version: {srv.version}</div>
            </div>
          ))}
        </div>
      </div>

      {/* RIGHT COLUMN: SERVER DETAILS & TOOLS */}
      <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", overflow: "hidden", display: "flex", flexDirection: "column" }}>
        {activeServer ? (
          <>
            <div style={{ padding: "20px", background: "#161b22", borderBottom: "1px solid #30363d" }}>
              <h3 style={{ margin: "0 0 5px 0", color: "#58a6ff", fontSize: "20px" }}>{activeServer.name} <span style={{ color: "#8b949e", fontSize: "14px", fontWeight: "normal" }}>({activeServer.id})</span></h3>
              <p style={{ margin: 0, color: "#c9d1d9" }}>Extending Swarm Context Capabilities via <strong>{activeServer.transport}</strong> Protocol.</p>
            </div>
            
            <div style={{ padding: "20px", flex: 1, overflowY: "auto" }}>
              <h4 style={{ color: "#c9d1d9", borderBottom: "1px solid #30363d", paddingBottom: "10px", marginTop: 0 }}>Registered MCP Tools ({activeServer.tools.length})</h4>
              {activeServer.tools.length === 0 ? (
                <div style={{ color: "#8b949e", fontStyle: "italic" }}>No tools exposed by this MCP server.</div>
              ) : (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "15px" }}>
                  {activeServer.tools.map((tool, idx) => (
                    <div key={idx} style={{ background: "#161b22", border: "1px solid #444c56", borderRadius: "6px", padding: "15px" }}>
                      <div style={{ color: "#d2a8ff", fontWeight: "bold", fontFamily: "monospace", fontSize: "14px", marginBottom: "8px" }}>
                        ⚡ {tool.name}
                      </div>
                      <div style={{ color: "#8b949e", fontSize: "13px", marginBottom: "12px", minHeight: "35px" }}>
                        {tool.description}
                      </div>
                      <div style={{ background: "#010409", padding: "8px", borderRadius: "4px", border: "1px solid #30363d" }}>
                        <div style={{ fontSize: "10px", color: "#8b949e", textTransform: "uppercase", marginBottom: "4px" }}>Input Schema</div>
                        <code style={{ color: "#79c0ff", fontSize: "12px", fontFamily: "monospace" }}>{tool.payload_schema}</code>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        ) : (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "#8b949e" }}>
            Select an MCP Server to view context capabilities.
          </div>
        )}
      </div>
    </div>
  );
}
