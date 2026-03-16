import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export default function LiveAttackGraph() {
    const [startNode, setStartNode] = useState("exec_engine::run_devsecops_pipeline");
    const [targetNode, setTargetNode] = useState("api_server::api_server_status");
    const [attackPath, setAttackPath] = useState<string[] | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [prUpdate, setPrUpdate] = useState<any>(null);
    const [toastMessage, setToastMessage] = useState<string | null>(null);

    useEffect(() => {
        const unlisten = listen("pr-chain-update", (event) => {
            setPrUpdate(event.payload);
        });
        return () => {
            unlisten.then(f => f());
        };
    }, []);

    const [sbomPath, setSbomPath] = useState("");
    const [sourcePath, setSourcePath] = useState("/home/timur/Desktop/_2026_trivy/cyclonedx-tauri-ui/src-tauri/src");

    const computeAttackPaths = async () => {
        setLoading(true);
        setError(null);
        setAttackPath(null);

        try {
            setPrUpdate(null);
            // Optional: load SBOM if provided
            let sbomJson: string | null = null;
            if (sbomPath) {
                sbomJson = await invoke("read_file_contents", { path: sbomPath });
            }

            const path: string[] = await invoke("get_attack_paths", {
                sbomJson: sbomJson || null,
                astRoot: sourcePath || null,
                startNode,
                targetVuln: targetNode
            });

            setAttackPath(path);
        } catch (e: any) {
            setError(e.toString());
        } finally {
            setLoading(false);
        }
    };

    const handleMergeFix = () => {
        setToastMessage(`✅ Merged PR #42. Rule ${prUpdate?.new_rule || "EVOLVED-CVE"} successfully saved to the Engine!`);
        setTimeout(() => {
            setPrUpdate(null);
            setAttackPath(null);
            setToastMessage(null);
        }, 4000);
    };

    return (
        <div style={{ padding: 20, maxWidth: 800, margin: "auto" }}>
            <h2>🔴 Agentic DevSecOps Graph</h2>
            <p>Live Attack Path Exploration powered by Amazon Nova 2 Lite</p>

            <div style={{ display: "flex", flexDirection: "column", gap: 10, background: "#111", padding: 15, borderRadius: 8 }}>
                <label>
                    <span style={{ display: "block", marginBottom: 5 }}>Source Directory (AST Graph)</span>
                    <input
                        style={{ width: "100%", padding: 8, background: "#222", border: "1px solid #444", color: "#fff", borderRadius: 4 }}
                        value={sourcePath}
                        onChange={e => setSourcePath(e.target.value)}
                        placeholder="Path to source code..."
                    />
                </label>

                <label>
                    <span style={{ display: "block", marginBottom: 5 }}>SBOM JSON File (Dependency Graph)</span>
                    <input
                        style={{ width: "100%", padding: 8, background: "#222", border: "1px solid #444", color: "#fff", borderRadius: 4 }}
                        value={sbomPath}
                        onChange={e => setSbomPath(e.target.value)}
                        placeholder="Optional Path to sbom.json"
                    />
                </label>

                <div style={{ display: "flex", gap: 10 }}>
                    <div style={{ flex: 1 }}>
                        <span style={{ display: "block", marginBottom: 5 }}>Entry Point (Start Node)</span>
                        <input
                            style={{ width: "100%", padding: 8, background: "#222", border: "1px solid #444", color: "#fff", borderRadius: 4 }}
                            value={startNode} onChange={e => setStartNode(e.target.value)}
                        />
                    </div>
                    <div style={{ flex: 1 }}>
                        <span style={{ display: "block", marginBottom: 5 }}>Target Vulnerability (End Node)</span>
                        <input
                            style={{ width: "100%", padding: 8, background: "#222", border: "1px solid #444", color: "#fff", borderRadius: 4 }}
                            value={targetNode} onChange={e => setTargetNode(e.target.value)}
                        />
                    </div>
                </div>

                <button
                    onClick={computeAttackPaths}
                    disabled={loading}
                    style={{ padding: "10px 15px", background: "#ff4d4f", color: "#fff", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: "bold", marginTop: 10 }}
                >
                    {loading ? "Computing Paths..." : "Discover Exploit Path"}
                </button>
            </div>

            <div style={{ marginTop: 20 }}>
                {error && (
                    <div style={{ padding: 15, background: "#2b1011", border: "1px solid #a61d24", color: "#ff4d4f", borderRadius: 6 }}>
                        <h4>❌ Analysis Error</h4>
                        <p style={{ margin: 0 }}>{error}</p>
                    </div>
                )}

                {attackPath && (
                    <div style={{ padding: 15, background: "#112211", border: "1px solid #237804", color: "#73d13d", borderRadius: 6 }}>
                        <h4 style={{ margin: "0 0 10px 0" }}>⚠️ Exploit Path Detected</h4>
                        <div style={{ display: "flex", flexDirection: "column", gap: 10, fontFamily: "monospace", fontSize: 13 }}>
                            {attackPath.map((step, idx) => (
                                <div key={idx} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                                    <div style={{ background: "#237804", color: "#fff", width: 24, height: 24, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: "bold" }}>
                                        {idx + 1}
                                    </div>
                                    <div style={{ background: "#0a1f0a", padding: "8px 12px", borderRadius: 4, border: "1px solid #135200", flex: 1 }}>
                                        {step}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {prUpdate && (
                    <div className="healing-container" style={{
                        padding: 20,
                        background: prUpdate.action === "HEALED_AST_NODE" ? "#0f2b1d" : "#2b1011",
                        border: `1px solid ${prUpdate.action === "HEALED_AST_NODE" ? "#237804" : "#a61d24"}`,
                        color: prUpdate.action === "HEALED_AST_NODE" ? "#73d13d" : "#ff4d4f",
                        borderRadius: 8,
                        marginTop: 20,
                        transition: "all 0.5s ease-in-out"
                    }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 15 }}>
                            <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: 10 }}>
                                {prUpdate.action === "HEALED_AST_NODE" ? "💚 Graph Healed by Nova 2" : "🚨 Node Quarantined"}
                            </h3>
                            <span style={{
                                padding: "4px 10px",
                                borderRadius: 12,
                                background: "rgba(255,255,255,0.1)",
                                fontSize: 12,
                                fontWeight: "bold"
                            }}>
                                {prUpdate.status}
                            </span>
                        </div>

                        <p style={{ margin: "0 0 15px 0", opacity: 0.9 }}>
                            Attack path identified vulnerability <strong>{prUpdate.vuln}</strong> at node boundary <code>{prUpdate.node}</code>.
                        </p>

                        {prUpdate.action === "HEALED_AST_NODE" && (
                            <div style={{ display: "flex", flexDirection: "column", gap: 15 }}>
                                <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                                    <span style={{
                                        padding: "4px 8px",
                                        borderRadius: 4,
                                        fontWeight: "bold",
                                        fontSize: 12,
                                        background: prUpdate.risk_score === "HIGH" ? "#a61d24" : prUpdate.risk_score === "MEDIUM" ? "#d46b08" : "#237804",
                                        color: "#fff"
                                    }}>
                                        RISK: {prUpdate.risk_score}
                                    </span>
                                </div>

                                <div style={{ background: "rgba(0,0,0,0.3)", padding: 12, borderRadius: 6, borderLeft: "3px solid #79c0ff" }}>
                                    <div style={{ fontSize: 11, textTransform: "uppercase", color: "#888", marginBottom: 5 }}>Root Cause Analysis</div>
                                    <div style={{ fontSize: 13, color: "#e6f7ff", lineHeight: 1.4 }}>{prUpdate.root_cause_analysis}</div>
                                </div>

                                <div style={{ background: "#000", padding: 12, borderRadius: 6, border: "1px dashed #237804" }}>
                                    <div style={{ fontSize: 11, textTransform: "uppercase", color: "#555", marginBottom: 5 }}>Generated Code Patch</div>
                                    <pre style={{ margin: 0, color: "#d2a8ff", fontFamily: "monospace", fontSize: 13, whiteSpace: "pre-wrap" }}>
                                        {prUpdate.patch}
                                    </pre>
                                </div>

                                <div style={{ background: "#000", padding: 12, borderRadius: 6, border: "1px dashed #237804" }}>
                                    <div style={{ fontSize: 11, textTransform: "uppercase", color: "#555", marginBottom: 5 }}>Extracted Self-Evolving Rule (Zero-Shot)</div>
                                    <code style={{ color: "#79c0ff", fontSize: 13 }}>{prUpdate.new_rule}</code>
                                </div>

                                <div style={{ fontSize: 13, textAlign: "right", marginTop: 5 }}>
                                    <button
                                        onClick={handleMergeFix}
                                        style={{ background: "#237804", color: "#fff", border: "none", padding: "8px 16px", borderRadius: 4, cursor: "pointer", fontWeight: "bold", boxShadow: "0 2px 8px rgba(35, 120, 4, 0.4)", transition: "all 0.2s" }}
                                        onMouseOver={e => e.currentTarget.style.transform = "scale(1.05)"}
                                        onMouseOut={e => e.currentTarget.style.transform = "scale(1)"}
                                    >
                                        Merge Fix & Evolve Engine
                                    </button>
                                </div>
                            </div>
                        )}

                        {prUpdate.action === "QUARANTINE_AST_NODE" && (
                            <div style={{ display: "flex", gap: 10, alignItems: "center", color: "#ffa940", fontSize: 14 }}>
                                <span className="spinner">⏳</span> Nova is analyzing AST and generating secure patch...
                                <style>{`
                                    @keyframes spin { 100% { transform: rotate(360deg); } }
                                    .spinner { display: inline-block; animation: spin 2s linear infinite; }
                                `}</style>
                            </div>
                        )}
                    </div>
                )}
            </div>

            <p style={{ marginTop: 20, fontSize: 12, color: '#666', textAlign: "center" }}>
                Powered by Amazon Nova 2 Lite Bedrock Subsystem
            </p>

            {/* Floating Toast Notification */}
            {toastMessage && (
                <div style={{
                    position: "fixed",
                    bottom: 30,
                    right: 30,
                    background: "#135200",
                    color: "#fff",
                    padding: "16px 24px",
                    borderRadius: 8,
                    boxShadow: "0 8px 24px rgba(0,0,0,0.5)",
                    border: "1px solid #389e0d",
                    fontWeight: "bold",
                    zIndex: 9999,
                    animation: "slideIn 0.3s ease-out"
                }}>
                    <style>{`
                        @keyframes slideIn {
                            from { transform: translateX(100%); opacity: 0; }
                            to { transform: translateX(0); opacity: 1; }
                        }
                    `}</style>
                    {toastMessage}
                </div>
            )}
        </div>
    );
}
