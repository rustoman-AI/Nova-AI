import { useState, useCallback, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";

// ─── Types ─────────────────────────────────
interface NodeDescriptor {
    node_type: string;
    label: string;
    icon: string;
    input_kinds: string[];
    output_kinds: string[];
    description: string;
}

interface PipelineNode {
    id: string;
    node_type: string;
    label: string;
    icon: string;
    config: Record<string, any>;
    status: "idle" | "running" | "done" | "failed" | "skipped" | "pending_approval";
    duration_ms?: number;
    error?: string;
    logs: string[];
    relevance_score?: number;
    requires_approval?: boolean;
}

interface EngineEvent {
    type: string;
    payload: any;
}

// ─── Main Component ────────────────────────────────
export default function DagPipelineBuilder() {
    const [nodeTypes, setNodeTypes] = useState<NodeDescriptor[]>([]);
    const [nodes, setNodes] = useState<PipelineNode[]>([]);
    const [workspace, setWorkspace] = useState("");
    const [running, setRunning] = useState(false);
    const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);
    const [selectedNode, setSelectedNode] = useState<string | null>(null);
    const [totalMs, setTotalMs] = useState(0);
    const logRef = useRef<HTMLDivElement>(null);

    // Load node types on mount
    useEffect(() => {
        invoke<NodeDescriptor[]>("engine_list_node_types").then(setNodeTypes).catch(() => { });
    }, []);

    // Listen for engine events
    useEffect(() => {
        const unlisten = listen<EngineEvent>("engine-event", (e) => {
            const evt = e.payload;
            if (!evt) return;
            const { type, payload } = evt;

            if (type === "NodeStarted") {
                setNodes(prev => prev.map(n =>
                    n.id === payload.node_id ? { ...n, status: "running" } : n
                ));
            } else if (type === "NodeFinished") {
                setNodes(prev => prev.map(n =>
                    n.id === payload.node_id ? { ...n, status: "done", duration_ms: payload.duration_ms } : n
                ));
            } else if (type === "NodeFailed") {
                setNodes(prev => prev.map(n =>
                    n.id === payload.node_id ? { ...n, status: "failed", error: payload.error } : n
                ));
            } else if (type === "NodeSkipped") {
                setNodes(prev => prev.map(n =>
                    n.id === payload.node_id ? { ...n, status: "skipped" } : n
                ));
            } else if (type === "NodePendingApproval") {
                setNodes(prev => prev.map(n =>
                    n.id === payload.node_id ? { ...n, status: "pending_approval" } : n
                ));
            } else if (type === "NodeRejected") {
                setNodes(prev => prev.map(n =>
                    n.id === payload.node_id ? { ...n, status: "failed", error: "Manually rejected by user" } : n
                ));
            } else if (type === "NodeLog") {
                setNodes(prev => prev.map(n =>
                    n.id === payload.node_id ? { ...n, logs: [...n.logs, payload.line] } : n
                ));
            } else if (type === "PipelineFinished") {
                setTotalMs(payload.total_ms);
                setRunning(false);
                setResult({ ok: true, msg: `✅ Done in ${payload.total_ms}ms — ${payload.nodes_executed} exec, ${payload.nodes_skipped} skipped` });
            } else if (type === "PipelineFailed") {
                setRunning(false);
                setResult({ ok: false, msg: `❌ Failed at ${payload.failed_node}: ${payload.error}` });
            }
        });
        return () => { unlisten.then(fn => fn()); };
    }, []);

    // Add node
    const addNode = useCallback((desc: NodeDescriptor) => {
        const id = `${desc.node_type}_${Date.now()}`;
        const config: Record<string, any> = {};

        // Default config based on node type
        if (desc.node_type === "validate") {
            config.input = "input.sbom";
            config.output = `validated_${id}`;
        } else if (desc.node_type === "nist_ssdf") {
            config.input = "input.sbom";
            config.output = `nist_ssdf_${id}`;
        } else if (desc.node_type === "cdxgen_scan") {
            config.input = "source";
            config.output = `scanned_${id}`;
            config.cdxgen_path = "cdxgen";
        } else if (desc.node_type === "merge") {
            config.inputs = ["a.sbom", "b.sbom"];
            config.output = `merged_${id}`;
        } else if (desc.node_type === "diff") {
            config.input_a = "a.sbom";
            config.input_b = "b.sbom";
            config.output = `diff_${id}`;
        } else if (desc.node_type === "sign") {
            config.input = "validated.sbom";
            config.output = `signed_${id}`;
        }

        setNodes(prev => [...prev, {
            id, node_type: desc.node_type, label: desc.label, icon: desc.icon,
            config, status: "idle", logs: [],
        }]);
    }, []);

    // Handle Manual Approval
    const approveNode = useCallback(async (id: string, approved: boolean) => {
        try {
            await invoke("engine_approve_node", { nodeId: id, approved });
            if (!approved) {
                setRunning(false);
                setResult({ ok: false, msg: `❌ Pipeline halted: Node ${id} was rejected.` });
            }
        } catch (e: any) {
            console.error("Failed to approve node:", e);
        }
    }, []);

    // Remove node
    const removeNode = useCallback((id: string) => {
        setNodes(prev => prev.filter(n => n.id !== id));
        if (selectedNode === id) setSelectedNode(null);
    }, [selectedNode]);

    // Update node config
    const updateConfig = useCallback((id: string, key: string, val: any) => {
        setNodes(prev => prev.map(n =>
            n.id === id ? { ...n, config: { ...n.config, [key]: val } } : n
        ));
    }, []);

    // Select workspace
    const selectWorkspace = useCallback(async () => {
        const f = await open({ directory: true, title: "Select workspace directory" });
        if (f) setWorkspace(f as string);
    }, []);

    // Execute pipeline
    const executePipeline = useCallback(async () => {
        if (!workspace || nodes.length === 0) return;

        // Reset statuses
        setNodes(prev => prev.map(n => ({ ...n, status: "idle" as const, logs: [], error: undefined, duration_ms: undefined })));
        setResult(null);
        setRunning(true);

        const pipeline = {
            nodes: nodes.map(n => ({
                id: n.id,
                node_type: n.node_type,
                config: n.config,
                requires_approval: n.config.requires_approval === true
            })),
            edges: [], // auto-wired by engine
            workspace,
            external_artifacts: [] as { id: string; kind: string; path: string }[],
        };

        try {
            await invoke<string>("engine_execute", { pipeline });
            // PipelineFinished event handles UI update
        } catch (e: any) {
            setRunning(false);
            setResult({ ok: false, msg: `❌ ${e}` });
        }
    }, [nodes, workspace]);

    // Memory Architecture: Snapshots
    const exportSnapshot = useCallback(async () => {
        if (!workspace || nodes.length === 0) return;
        try {
            const path = await invoke<string>("engine_export_snapshot", { workspace, nodes });
            setResult({ ok: true, msg: `📸 Snapshot saved to ${path}` });
        } catch(e: any) {
            setResult({ ok: false, msg: `❌ Failed to save snapshot: ${e}` });
        }
    }, [workspace, nodes]);

    const restoreSnapshot = useCallback(async () => {
        if (!workspace) return;
        try {
            const restored = await invoke<PipelineNode[]>("engine_restore_snapshot", { workspace });
            setNodes(restored);
            setResult({ ok: true, msg: `🧬 Snapshot restored successfully` });
        } catch(e: any) {
            setResult({ ok: false, msg: `❌ Failed to restore snapshot: ${e}` });
        }
    }, [workspace]);

    // Memory Architecture: Time Decay
    const applyDecay = useCallback(async () => {
        if (nodes.length === 0) return;
        try {
            const decayed = await invoke<PipelineNode[]>("engine_apply_decay", { nodes });
            setNodes(decayed);
            setResult({ ok: true, msg: `⏳ Accelerated Time Decay applied` });
        } catch(e: any) {
            setResult({ ok: false, msg: `❌ Failed to apply decay: ${e}` });
        }
    }, [nodes]);

    const sel = nodes.find(n => n.id === selectedNode);

    return (
        <div className="dag-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">DAG Pipeline Builder</h2>
                <div className="depgraph-stats">
                    <span className="depgraph-stat">{nodes.length} nodes</span>
                    {totalMs > 0 && <span className="depgraph-stat">{totalMs}ms</span>}
                </div>
            </div>

            <div className="dag-content">
                {/* Left: node palette */}
                <div className="dag-palette">
                    <div className="dag-palette-title">Node Types</div>
                    {nodeTypes.map(nt => (
                        <div key={nt.node_type} className="dag-palette-node" onClick={() => addNode(nt)} title={nt.description}>
                            <span className="dag-palette-icon">{nt.icon}</span>
                            <span className="dag-palette-label">{nt.label}</span>
                        </div>
                    ))}
                    <div className="dag-palette-divider" />
                    <div className="dag-palette-node" onClick={selectWorkspace}>
                        <span className="dag-palette-icon">📂</span>
                        <span className="dag-palette-label">Workspace</span>
                    </div>
                    {workspace && <div className="dag-workspace-path">{workspace.split("/").pop()}</div>}
                </div>

                {/* Center: pipeline canvas */}
                <div className="dag-canvas">
                    {nodes.length === 0 ? (
                        <div className="pipe-empty" style={{ padding: "40px 20px" }}>
                            <span className="pipe-empty-icon">🔧</span>
                            <h3>Build Your Pipeline</h3>
                            <p>Click node types on the left to add them. Configure artifact IDs to wire the DAG.</p>
                        </div>
                    ) : (
                        <div className="dag-nodes">
                            {nodes.map((n, i) => (
                                <div key={n.id}
                                    style={{ opacity: Math.max(0.3, n.relevance_score ?? 1.0) }}
                                    className={`dag-node dag-node-${n.status} ${selectedNode === n.id ? "dag-node-selected" : ""}`}
                                    onClick={() => setSelectedNode(n.id)}
                                >
                                    <div className="dag-node-header">
                                        <span className="dag-node-icon">{n.icon}</span>
                                        <span className="dag-node-label">{n.label}</span>
                                        <span className={`dag-node-status dag-status-${n.status}`}>
                                            {n.status === "running" ? "⏳" : n.status === "done" ? "✅" : n.status === "failed" ? "❌" : n.status === "skipped" ? "⏭️" : "⚪"}
                                        </span>
                                        <button className="dag-node-remove" onClick={(e) => { e.stopPropagation(); removeNode(n.id); }}>×</button>
                                    </div>
                                    <div className="dag-node-meta">
                                        <span className="dag-node-id">{n.id.slice(0, 20)}</span>
                                        {n.duration_ms !== undefined && <span className="dag-node-dur">{n.duration_ms}ms</span>}
                                    </div>
                                    {n.error && <div className="dag-node-error">{n.error.slice(0, 80)}</div>}
                                    {n.status === "pending_approval" && (
                                        <div className="sop-approval-actions">
                                            <div className="sop-approval-label">SOP: Manual Approval Required</div>
                                            <div style={{ display: "flex", gap: "8px" }}>
                                                <button className="sop-btn approve" onClick={(e) => { e.stopPropagation(); approveNode(n.id, true); }}>✅ Approve</button>
                                                <button className="sop-btn reject" onClick={(e) => { e.stopPropagation(); approveNode(n.id, false); }}>❌ Reject</button>
                                            </div>
                                        </div>
                                    )}
                                    {i < nodes.length - 1 && <div className="dag-arrow">↓</div>}
                                </div>
                            ))}
                        </div>
                    )}

                    {/* Execute bar */}
                    <div className="dag-exec-bar">
                        <div style={{ display: 'flex', gap: '8px' }}>
                            <button className="exec-btn" onClick={executePipeline}
                                disabled={running || !workspace || nodes.length === 0}
                            >
                                {running ? "⏳ Running..." : "▶ Execute Pipeline"}
                            </button>
                            
                            <button className="exec-btn" style={{background: '#2c3e50'}} onClick={exportSnapshot} disabled={!workspace || nodes.length === 0} title="Export architecture state to JSON">
                                📸 Snapshot
                            </button>
                            <button className="exec-btn" style={{background: '#2c3e50'}} onClick={restoreSnapshot} disabled={!workspace} title="Restore architecture state from JSON">
                                🧬 Restore
                            </button>
                            <button className="exec-btn" style={{background: '#8e44ad'}} onClick={applyDecay} disabled={nodes.length === 0} title="Fast-forward Time Decay to test Relevance architecture">
                                ⏳ Decay
                            </button>
                        </div>
                        {result && (
                            <span className={`dag-result ${result.ok ? "dag-result-ok" : "dag-result-err"}`}>
                                {result.msg}
                            </span>
                        )}
                    </div>
                </div>

                {/* Right: config panel */}
                <div className="dag-config">
                    {sel ? (
                        <div className="dag-config-inner">
                            <h4>{sel.icon} {sel.label}</h4>
                            <div className="genwiz-row checkbox-row">
                                <label>
                                    <input 
                                        type="checkbox" 
                                        checked={sel.config.requires_approval === true}
                                        onChange={e => updateConfig(sel.id, 'requires_approval', e.target.checked)}
                                    />
                                    Requires Manual Approval (SOP)
                                </label>
                            </div>
                            {Object.entries(sel.config).filter(([k]) => k !== 'requires_approval').map(([key, val]) => (
                                <div key={key} className="genwiz-row">
                                    <label>{key}</label>
                                    {Array.isArray(val) ? (
                                        <input value={(val as string[]).join(", ")}
                                            onChange={e => updateConfig(sel.id, key, e.target.value.split(",").map(s => s.trim()))}
                                        />
                                    ) : (
                                        <input value={String(val)}
                                            onChange={e => updateConfig(sel.id, key, e.target.value)}
                                        />
                                    )}
                                </div>
                            ))}
                            {/* Logs */}
                            {sel.logs.length > 0 && (
                                <div className="dag-logs" ref={logRef}>
                                    <div className="dag-logs-title">📋 Logs</div>
                                    {sel.logs.map((l, i) => <div key={i} className="dag-log-line">{l}</div>)}
                                </div>
                            )}
                        </div>
                    ) : (
                        <div className="dag-config-empty">Select a node to configure</div>
                    )}
                </div>
            </div>
        </div>
    );
}
