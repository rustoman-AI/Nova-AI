import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";

interface PlaybookStep {
    id: string;
    title: string;
    description: string;
    status: string; // "pending", "running", "completed", "failed"
    executor: string;
}

interface IncidentPlaybook {
    incident_id: string;
    severity: string;
    scenario_name: string;
    description: string;
    steps: PlaybookStep[];
}

interface StepExecutionResult {
    step_id: string;
    success: boolean;
    logs: string[];
}

export default function IncidentPlaybooks() {
    const [playbooks, setPlaybooks] = useState<IncidentPlaybook[]>([]);
    const [activePlaybookId, setActivePlaybookId] = useState<string | null>(null);
    const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
    const consoleRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        loadPlaybooks();
    }, []);

    useEffect(() => {
        if (consoleRef.current) {
            consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
        }
    }, [terminalLogs]);

    const loadPlaybooks = async () => {
        try {
            const data = await invoke<IncidentPlaybook[]>("engine_get_incident_playbooks");
            setPlaybooks(data);
            if (data.length > 0) setActivePlaybookId(data[0].incident_id);
        } catch (err) {
            console.error("Failed to load SOAR playbooks", err);
        }
    };

    const activePlaybook = playbooks.find(p => p.incident_id === activePlaybookId);

    const executeStep = async (stepId: string, executor: string) => {
        if (!activePlaybookId) return;

        // Optimistically update status to 'running'
        setPlaybooks(prev => prev.map(pb => {
            if (pb.incident_id !== activePlaybookId) return pb;
            return {
                ...pb,
                steps: pb.steps.map(s => s.id === stepId ? { ...s, status: "running" } : s)
            };
        }));

        setTerminalLogs(prev => [...prev, `[SYSTEM] Initiating Execution Engine for step ${stepId}...`]);

        try {
            const result = await invoke<StepExecutionResult>("engine_execute_playbook_step", {
                incidentId: activePlaybookId,
                stepId,
                executor
            });

            // Update status based on result
            setPlaybooks(prev => prev.map(pb => {
                if (pb.incident_id !== activePlaybookId) return pb;
                return {
                    ...pb,
                    steps: pb.steps.map(s => s.id === stepId ? { ...s, status: result.success ? "completed" : "failed" } : s)
                };
            }));

            // Append execution logs
            result.logs.forEach((log, idx) => {
                setTimeout(() => {
                    setTerminalLogs(prev => [...prev, log]);
                }, idx * 150); // Small delay for visual streaming effect
            });

        } catch (err: any) {
            setTerminalLogs(prev => [...prev, `[FATAL] Execution failed: ${err.toString()}`]);
            setPlaybooks(prev => prev.map(pb => {
                if (pb.incident_id !== activePlaybookId) return pb;
                return {
                    ...pb,
                    steps: pb.steps.map(s => s.id === stepId ? { ...s, status: "failed" } : s)
                };
            }));
        }
    };

    const getSeverityColor = (sev: string) => {
        switch (sev.toUpperCase()) {
            case "CRITICAL": return "#ff7b72"; // Red
            case "HIGH": return "#ffa657"; // Orange
            case "MEDIUM": return "#d2a8ff"; // Purple
            default: return "#58a6ff"; // Blue
        }
    };

    const getStatusBadge = (status: string) => {
        if (status === "completed") return <span style={{ color: "#3fb950", border: "1px solid #3fb950", padding: "2px 6px", borderRadius: "4px", fontSize: "11px", fontWeight: "bold" }}>COMPLETED</span>;
        if (status === "running") return <span style={{ color: "#d2a8ff", border: "1px solid #d2a8ff", padding: "2px 6px", borderRadius: "4px", fontSize: "11px", fontWeight: "bold" }}>EXECUTING...</span>;
        if (status === "failed") return <span style={{ color: "#ff7b72", border: "1px solid #ff7b72", padding: "2px 6px", borderRadius: "4px", fontSize: "11px", fontWeight: "bold" }}>FAILED</span>;
        return <span style={{ color: "#8b949e", border: "1px solid #30363d", padding: "2px 6px", borderRadius: "4px", fontSize: "11px" }}>PENDING</span>;
    };

    return (
        <div style={{ padding: "30px", maxWidth: "1200px", margin: "auto", color: "#c9d1d9", height: "100%", display: "flex", flexDirection: "column" }}>
            <div style={{ marginBottom: "20px" }}>
                <h2 style={{ margin: "0 0 5px 0", fontSize: "24px", color: "#ffa657" }}>📖 SOAR Incident Operations</h2>
                <p style={{ color: "#8b949e", margin: 0 }}>Automated orchestration pipelines for threat containment and remediation.</p>
            </div>

            <div style={{ display: "flex", gap: "20px", flex: 1, minHeight: 0 }}>
                {/* Left Panel: Scenarios */}
                <div style={{ width: "350px", display: "flex", flexDirection: "column", gap: "15px", overflowY: "auto", paddingRight: "5px" }}>
                    {playbooks.map(pb => (
                        <div 
                            key={pb.incident_id}
                            onClick={() => setActivePlaybookId(pb.incident_id)}
                            style={{ 
                                padding: "15px", 
                                background: activePlaybookId === pb.incident_id ? "#1f2937" : "#0d1117", 
                                border: `1px solid ${activePlaybookId === pb.incident_id ? "#58a6ff" : "#30363d"}`, 
                                borderRadius: "8px", 
                                cursor: "pointer",
                                transition: "all 0.2s"
                            }}
                        >
                            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                                <span style={{ fontWeight: "bold", color: "#c9d1d9" }}>{pb.incident_id}</span>
                                <span style={{ color: getSeverityColor(pb.severity), fontSize: "12px", border: `1px solid ${getSeverityColor(pb.severity)}`, padding: "2px 6px", borderRadius: "10px" }}>{pb.severity}</span>
                            </div>
                            <div style={{ fontSize: "14px", color: activePlaybookId === pb.incident_id ? "#58a6ff" : "#8b949e", fontWeight: "bold", marginBottom: "8px" }}>{pb.scenario_name}</div>
                            <div style={{ fontSize: "12px", color: "#8b949e", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{pb.description}</div>
                        </div>
                    ))}
                </div>

                {/* Right Panel: Active Playbook Timeline & Terminal */}
                {activePlaybook ? (
                    <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: "20px", overflowY: "auto", paddingRight: "5px" }}>
                        <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", padding: "20px" }}>
                            <h3 style={{ margin: "0 0 10px 0", color: "#e6edf3" }}>Active Containment Plan</h3>
                            <p style={{ color: "#8b949e", fontSize: "14px", marginTop: 0, marginBottom: "25px" }}>{activePlaybook.description}</p>
                            
                            {/* Process Timeline */}
                            <div style={{ display: "flex", flexDirection: "column", gap: "15px", position: "relative" }}>
                                {/* Decorative line connecting steps */}
                                <div style={{ position: "absolute", left: "11px", top: "20px", bottom: "20px", width: "2px", background: "#30363d", zIndex: 0 }}></div>

                                {activePlaybook.steps.map((step, idx) => (
                                    <div key={step.id} style={{ display: "flex", gap: "15px", position: "relative", zIndex: 1, alignItems: "flex-start" }}>
                                        <div style={{ width: "24px", height: "24px", borderRadius: "50%", background: step.status === "completed" ? "#238636" : (step.status === "running" ? "#8957e5" : "#21262d"), border: `2px solid ${step.status === "completed" ? "#3fb950" : (step.status === "running" ? "#d2a8ff" : "#444c56")}`, display: "flex", alignItems: "center", justifyContent: "center", color: "white", fontSize: "12px", fontWeight: "bold", flexShrink: 0 }}>
                                            {step.status === "completed" ? "✓" : (idx + 1)}
                                        </div>
                                        <div style={{ flex: 1, background: "#161b22", border: "1px solid #30363d", borderRadius: "8px", padding: "15px" }}>
                                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
                                                <div>
                                                    <div style={{ fontWeight: "bold", color: "#c9d1d9", fontSize: "15px" }}>{step.title}</div>
                                                    <div style={{ color: "#8b949e", fontSize: "13px", marginTop: "4px" }}>{step.description}</div>
                                                </div>
                                                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "8px" }}>
                                                    {getStatusBadge(step.status)}
                                                    {step.status !== "completed" && step.status !== "running" && (
                                                        <button 
                                                            onClick={() => executeStep(step.id, step.executor)}
                                                            style={{ padding: "6px 12px", background: "#21262d", color: "#c9d1d9", border: "1px solid #30363d", borderRadius: "6px", cursor: "pointer", fontSize: "12px", fontWeight: "bold", transition: "all 0.2s" }}
                                                            onMouseEnter={(e) => { e.currentTarget.style.background = "#30363d"; e.currentTarget.style.color = "white"; }}
                                                            onMouseLeave={(e) => { e.currentTarget.style.background = "#21262d"; e.currentTarget.style.color = "#c9d1d9"; }}
                                                        >
                                                            ⚡ Execute
                                                        </button>
                                                    )}
                                                </div>
                                            </div>
                                            <div style={{ fontSize: "11px", color: "#58a6ff", fontFamily: "monospace" }}>Executor Target: {step.executor}</div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Integration Terminal */}
                        <div style={{ background: "#010409", border: "1px solid #30363d", borderRadius: "8px", display: "flex", flexDirection: "column", minHeight: "250px", flexShrink: 0 }}>
                            <div style={{ padding: "10px 15px", background: "#161b22", borderBottom: "1px solid #30363d", display: "flex", gap: "8px", alignItems: "center" }}>
                                <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#ff5f56" }}></div>
                                <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#ffbd2e" }}></div>
                                <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#27c93f" }}></div>
                                <span style={{ marginLeft: "10px", color: "#8b949e", fontSize: "12px", fontFamily: "monospace" }}>tty: soar-orchestrator-output</span>
                            </div>
                            <div ref={consoleRef} style={{ padding: "15px", overflowY: "auto", flex: 1, fontFamily: "monospace", fontSize: "13px", lineHeight: "1.5" }}>
                                {terminalLogs.length === 0 ? (
                                    <div style={{ color: "#6e7681", fontStyle: "italic" }}>Waiting for operational triggers...</div>
                                ) : (
                                    terminalLogs.map((log, i) => {
                                        let color = "#c9d1d9";
                                        if (log.includes("[ERROR]") || log.includes("[FATAL]")) color = "#ff7b72";
                                        if (log.includes("Status: ") || log.includes("[SUCCESS]")) color = "#3fb950";
                                        if (log.includes("[SOAR]")) color = "#ffa657";
                                        if (log.includes("[K8S]")) color = "#326ce5"; // K8s blue
                                        if (log.includes("[AWS IAM]")) color = "#ff9900"; // AWS orange
                                        if (log.includes("[MCP HUB]")) color = "#d2a8ff"; // Purple
                                        if (log.includes("[SLACK]")) color = "#e01e5a"; // Slack red

                                        return (
                                            <div key={i} style={{ color, marginBottom: "4px" }}>
                                                <span style={{ color: "#6e7681", marginRight: "10px" }}>{new Date().toISOString().split('T')[1].slice(0, 12)}</span>
                                                {log}
                                            </div>
                                        );
                                    })
                                )}
                            </div>
                        </div>
                    </div>
                ) : (
                    <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", border: "1px dashed #30363d", borderRadius: "8px", background: "#0d1117", color: "#8b949e" }}>
                        Select a Playbook to view orchestration details.
                    </div>
                )}
            </div>
        </div>
    );
}
