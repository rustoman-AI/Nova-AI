import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";

interface WizardOnboardingResult {
    repository: string;
    ast_nodes_scanned: number;
    cve_detected: number;
    swarm_agents_deployed: number;
    status: string;
}

export default function WizardPanel() {
    const [step, setStep] = useState(1);
    const [repository, setRepository] = useState("https://github.com/OWASP/NodeGoat");
    const [sastEnabled, setSastEnabled] = useState(true);
    const [trivyEnabled, setTrivyEnabled] = useState(true);
    const [ragEnabled, setRagEnabled] = useState(true);
    
    const [pipelineLogs, setPipelineLogs] = useState<string[]>([]);
    const [pipelineActive, setPipelineActive] = useState(false);
    const [onboardingResult, setOnboardingResult] = useState<WizardOnboardingResult | null>(null);

    const terminalRef = useRef<HTMLDivElement>(null);
    const unlistenRef = useRef<UnlistenFn | null>(null);

    useEffect(() => {
        if (terminalRef.current) {
            terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
        }
    }, [pipelineLogs]);

    useEffect(() => {
        // Setup listener for pipeline streams
        const setupListener = async () => {
            unlistenRef.current = await listen<string>("wizard-pipeline-log", (event) => {
                setPipelineLogs(prev => [...prev, event.payload]);
            });
        };
        setupListener();

        return () => {
            if (unlistenRef.current) unlistenRef.current();
        };
    }, []);

    const startPipeline = async () => {
        setStep(3);
        setPipelineActive(true);
        setPipelineLogs(["[INIT] Bootstrapping Multi-Vector Threat Analysis Pipeline..."]);

        try {
            // Determine if we are running in a real Tauri context
            const isTauri = typeof window !== 'undefined' && 'window' in globalThis && '__TAURI_INTERNALS__' in window;
            
            let result: WizardOnboardingResult;
            if (isTauri) {
                result = await invoke<WizardOnboardingResult>("engine_run_onboarding_pipeline", { repository });
            } else {
                // Fallback mock for browser-based UI validation
                const fakeLogs = [
                    "[GIT] Cloning source structures and extracting metadata...",
                    "[AST] Compiled 13402 internal abstract syntax tree nodes.",
                    "[TRIVY] Scanning finalized. Intercepted 8 potential CVE vectors.",
                    "[SOM] Synthesizing Component Bill of Materials mapping (CycloneDX v1.6)...",
                    "SWARM] Bootstrapping autonomous agent defenses...",
                    "[GRAPH] Projecting aggregated telemetry into the 3D Universe and live data models...",
                    "[SUCCESS] DevSecOps Pipeline Initialization Complete."
                ];
                for (let i = 0; i < fakeLogs.length; i++) {
                    await new Promise(r => setTimeout(r, 600));
                    setPipelineLogs(prev => [...prev, fakeLogs[i]]);
                }
                result = {
                    repository,
                    ast_nodes_scanned: 13402,
                    cve_detected: 8,
                    swarm_agents_deployed: 14,
                    status: "SUCCESS"
                };
            }
            
            setOnboardingResult(result);
            setPipelineActive(false);
            setTimeout(() => setStep(4), 1000); // Transition to success step
        } catch (err: any) {
            setPipelineLogs(prev => [...prev, `[FATAL] Pipeline orchestration broke: ${err?.message || err.toString()}`]);
            setPipelineActive(false);
        }
    };

    const renderStep1 = () => (
        <div style={{ animation: "fadeIn 0.5s ease" }}>
            <h2 style={{ color: "#e6edf3", fontSize: "24px", marginBottom: "10px" }}>Connect Source Repository</h2>
            <p style={{ color: "#8b949e", marginBottom: "25px" }}>Specify the Git target to ingest into the DevSecOps Graph Space.</p>
            
            <div style={{ background: "#0d1117", padding: "20px", borderRadius: "8px", border: "1px solid #30363d" }}>
                <label style={{ display: "block", color: "#c9d1d9", marginBottom: "8px", fontWeight: "bold" }}>Repository URL</label>
                <input 
                    type="text" 
                    value={repository} 
                    onChange={e => setRepository(e.target.value)}
                    style={{ width: "100%", padding: "12px", background: "#161b22", border: "1px solid #30363d", color: "#e6edf3", borderRadius: "6px", fontFamily: "monospace", fontSize: "14px", boxSizing: "border-box" }}
                />
                
                <div style={{ marginTop: "20px", display: "flex", gap: "15px" }}>
                    <div style={{ flex: 1 }}>
                        <label style={{ display: "block", color: "#c9d1d9", marginBottom: "8px", fontWeight: "bold" }}>Target Branch</label>
                        <input type="text" defaultValue="main" style={{ width: "100%", padding: "12px", background: "#161b22", border: "1px solid #30363d", color: "#e6edf3", borderRadius: "6px", boxSizing: "border-box" }} />
                    </div>
                    <div style={{ flex: 1 }}>
                        <label style={{ display: "block", color: "#c9d1d9", marginBottom: "8px", fontWeight: "bold" }}>Authentication</label>
                        <select style={{ width: "100%", padding: "12px", background: "#161b22", border: "1px solid #30363d", color: "#e6edf3", borderRadius: "6px", boxSizing: "border-box" }}>
                            <option>GitHub OAuth Context</option>
                            <option>Personal Access Token</option>
                            <option>Public / Unauthenticated</option>
                        </select>
                    </div>
                </div>
            </div>
            
            <div style={{ marginTop: "30px", display: "flex", justifyContent: "flex-end" }}>
                <button onClick={() => setStep(2)} style={{ padding: "10px 25px", background: "#1f6feb", color: "white", border: "none", borderRadius: "6px", fontWeight: "bold", cursor: "pointer" }}>Configure Security Tooling →</button>
            </div>
        </div>
    );

    const renderStep2 = () => (
        <div style={{ animation: "fadeIn 0.5s ease" }}>
            <h2 style={{ color: "#e6edf3", fontSize: "24px", marginBottom: "10px" }}>Select Analysis Tiers</h2>
            <p style={{ color: "#8b949e", marginBottom: "25px" }}>Activate the multi-vector defense sensors for this repository.</p>
            
            <div style={{ display: "flex", flexDirection: "column", gap: "15px" }}>
                {renderToggle("AST Code Intelligence", "Tree-sitter driven SAST and Semantic Graphing.", sastEnabled, setSastEnabled)}
                {renderToggle("Trivy Vulnerability Scanner", "Deep container, OS packages, and dependency matching.", trivyEnabled, setTrivyEnabled)}
                {renderToggle("Vector RAG Agents", "AI-driven architecture ingestion and swarm defensive chat.", ragEnabled, setRagEnabled)}
            </div>
            
            <div style={{ marginTop: "30px", display: "flex", justifyContent: "space-between" }}>
                <button onClick={() => setStep(1)} style={{ padding: "10px 25px", background: "#21262d", color: "#c9d1d9", border: "1px solid #30363d", borderRadius: "6px", cursor: "pointer" }}>← Back</button>
                <button onClick={startPipeline} style={{ padding: "10px 25px", background: "#238636", color: "white", border: "none", borderRadius: "6px", fontWeight: "bold", cursor: "pointer", display: "flex", alignItems: "center", gap: "8px" }}>
                    🚀 Initialize Control Plane
                </button>
            </div>
        </div>
    );

    const renderToggle = (title: string, desc: string, active: boolean, setter: (val: boolean) => void) => (
        <div 
            onClick={() => setter(!active)}
            style={{ display: "flex", alignItems: "center", justifyContent: "space-between", background: active ? "#1f2937" : "#0d1117", border: active ? "1px solid #58a6ff" : "1px solid #30363d", padding: "20px", borderRadius: "8px", cursor: "pointer", transition: "all 0.2s" }}
        >
            <div>
                <div style={{ color: active ? "#e6edf3" : "#8b949e", fontWeight: "bold", fontSize: "16px", marginBottom: "4px" }}>{title}</div>
                <div style={{ color: "#8b949e", fontSize: "13px" }}>{desc}</div>
            </div>
            <div style={{ width: "40px", height: "22px", background: active ? "#238636" : "#21262d", borderRadius: "11px", position: "relative", transition: "all 0.3s" }}>
                <div style={{ position: "absolute", top: "2px", left: active ? "20px" : "2px", width: "18px", height: "18px", background: "white", borderRadius: "50%", transition: "all 0.3s" }}></div>
            </div>
        </div>
    );

    const renderStep3 = () => (
        <div style={{ animation: "fadeIn 0.5s ease", display: "flex", flexDirection: "column", height: "100%" }}>
            <h2 style={{ color: "#e6edf3", fontSize: "24px", marginBottom: "10px", display: "flex", alignItems: "center", gap: "10px" }}>
                {pipelineActive && <span style={{ animation: "spin 2s linear infinite", display: "inline-block" }}>⚙️</span>}
                In-Flight Pipeline Orchestration
            </h2>
            <p style={{ color: "#8b949e", marginBottom: "20px" }}>Synthesizing the AST models, querying CVE databases, and activating WASM plugins...</p>
            
            <div style={{ flex: 1, background: "#010409", border: "1px solid #30363d", borderRadius: "8px", display: "flex", flexDirection: "column", overflow: "hidden" }}>
                <div style={{ padding: "10px 15px", background: "#161b22", borderBottom: "1px solid #30363d", display: "flex", alignItems: "center" }}>
                    <div style={{ display: "flex", gap: "6px", marginRight: "10px" }}>
                        <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#ff5f56" }}></div>
                        <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#ffbd2e" }}></div>
                        <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#27c93f" }}></div>
                    </div>
                    <span style={{ color: "#8b949e", fontSize: "12px", fontFamily: "monospace" }}>tty: onboarding-orchestrator</span>
                </div>
                <div ref={terminalRef} style={{ padding: "15px", flex: 1, overflowY: "auto", fontFamily: "monospace", fontSize: "14px", lineHeight: "1.6" }}>
                    {pipelineLogs.map((log, idx) => {
                        let color = "#c9d1d9";
                        if (log.includes("[SYSTEM]")) color = "#58a6ff";
                        if (log.includes("[GIT]")) color = "#ffa657";
                        if (log.includes("[AST]")) color = "#d2a8ff";
                        if (log.includes("[TRIVY]")) color = "#ff7b72";
                        if (log.includes("[SBOM]") || log.includes("[GRAPH]")) color = "#3fb950";
                        if (log.includes("[SUCCESS]")) color = "#2ea043";

                        return (
                            <div key={idx} style={{ color, marginBottom: "4px" }}>
                                <span style={{ color: "#6e7681", marginRight: "12px" }}>{new Date().toISOString().split('T')[1].slice(0, 12)}</span>
                                {log}
                            </div>
                        );
                    })}
                    {pipelineActive && <div style={{ color: "#58a6ff", marginTop: "10px", animation: "pulse 1.5s infinite" }}>█</div>}
                </div>
            </div>
        </div>
    );

    const renderStep4 = () => (
        <div style={{ animation: "fadeIn 0.5s ease", textAlign: "center", padding: "40px 20px" }}>
            <div style={{ fontSize: "64px", marginBottom: "20px" }}>🎉</div>
            <h2 style={{ color: "#3fb950", fontSize: "32px", marginBottom: "10px" }}>Onboarding Successful</h2>
            <p style={{ color: "#8b949e", fontSize: "16px", maxWidth: "600px", margin: "0 auto 40px auto" }}>
                Repository <strong>{onboardingResult?.repository}</strong> has been fully ingested into the DevSecOps Control Plane. 
                The multi-vector security graphs and AI swarms are online.
            </p>
            
            <div style={{ display: "flex", justifyContent: "center", gap: "20px", marginBottom: "40px" }}>
                <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", padding: "20px", width: "180px" }}>
                    <div style={{ fontSize: "28px", color: "#58a6ff", fontWeight: "bold", marginBottom: "5px" }}>{onboardingResult?.ast_nodes_scanned.toLocaleString()}</div>
                    <div style={{ color: "#8b949e", fontSize: "12px", textTransform: "uppercase" }}>AST Nodes Mapped</div>
                </div>
                <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", padding: "20px", width: "180px" }}>
                    <div style={{ fontSize: "28px", color: "#ff7b72", fontWeight: "bold", marginBottom: "5px" }}>{onboardingResult?.cve_detected}</div>
                    <div style={{ color: "#8b949e", fontSize: "12px", textTransform: "uppercase" }}>CVEs Detected</div>
                </div>
                <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", padding: "20px", width: "180px" }}>
                    <div style={{ fontSize: "28px", color: "#d2a8ff", fontWeight: "bold", marginBottom: "5px" }}>{onboardingResult?.swarm_agents_deployed}</div>
                    <div style={{ color: "#8b949e", fontSize: "12px", textTransform: "uppercase" }}>Swarm Bots Active</div>
                </div>
            </div>

            <div style={{ display: "flex", justifyContent: "center", gap: "15px" }}>
                <button style={{ padding: "12px 25px", background: "#f85149", color: "white", border: "none", borderRadius: "6px", fontWeight: "bold", cursor: "pointer", fontSize: "15px" }}>
                    👁️ View Agentic Dashboard
                </button>
                <button style={{ padding: "12px 25px", background: "#21262d", color: "#c9d1d9", border: "1px solid #30363d", borderRadius: "6px", fontWeight: "bold", cursor: "pointer", fontSize: "15px" }}>
                    🌌 Enter 3D Universe
                </button>
            </div>
        </div>
    );

    return (
        <div style={{ padding: "40px", maxWidth: "1000px", margin: "auto", color: "#c9d1d9", height: "100%", display: "flex", flexDirection: "column" }}>
            {/* Header */}
            <div style={{ textAlign: "center", marginBottom: "40px" }}>
                <h1 style={{ fontSize: "32px", color: "#fff", margin: "0 0 10px 0" }}>🪄 Control Plane Wizard</h1>
                <p style={{ color: "#8b949e", fontSize: "16px", margin: 0 }}>Onboard, scan, and deploy the AI Swarm across your repositories.</p>
            </div>

            {/* Stepper Progress */}
            <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: "15px", marginBottom: "40px" }}>
                {[
                    { num: 1, label: "Source" },
                    { num: 2, label: "Tiers" },
                    { num: 3, label: "Orchestration" },
                    { num: 4, label: "Result" }
                ].map((s, i) => (
                    <div key={s.num} style={{ display: "flex", alignItems: "center", gap: "15px" }}>
                        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "8px", width: "80px" }}>
                            <div style={{ 
                                width: "36px", height: "36px", borderRadius: "50%", 
                                background: step >= s.num ? "#1f6feb" : "#21262d", 
                                color: "white", display: "flex", alignItems: "center", justifyContent: "center", 
                                fontWeight: "bold", border: step >= s.num ? "none" : "1px solid #30363d" 
                            }}>
                                {step > s.num ? "✓" : s.num}
                            </div>
                            <span style={{ fontSize: "12px", color: step >= s.num ? "#c9d1d9" : "#6e7681", fontWeight: step === s.num ? "bold" : "normal" }}>{s.label}</span>
                        </div>
                        {i < 3 && <div style={{ height: "2px", width: "80px", background: step > s.num ? "#1f6feb" : "#30363d", marginTop: "-20px" }}></div>}
                    </div>
                ))}
            </div>

            {/* Active Step Content */}
            <div style={{ flex: 1, minHeight: 0 }}>
                {step === 1 && renderStep1()}
                {step === 2 && renderStep2()}
                {step === 3 && renderStep3()}
                {step === 4 && renderStep4()}
            </div>
            
            <style>{`
                @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
                @keyframes spin { 100% { transform: rotate(360deg); } }
            `}</style>
        </div>
    );
}
