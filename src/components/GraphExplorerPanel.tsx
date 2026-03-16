import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
    ReactFlow,
    Background,
    Controls,
    MiniMap,
    useNodesState,
    useEdgesState,
    Handle,
    Position,
    MarkerType,
    type Node,
    type Edge,
    type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

interface GNode { id: string; label: string; kind: string; color: string; icon: string; size: number; details: Record<string, string>; }
interface GEdge { from: string; to: string; kind: string; label: string; color: string; dashed: boolean; }
interface GraphViewStats { total_nodes: number; component_nodes: number; vuln_nodes: number; license_nodes: number; supplier_nodes: number; pipeline_nodes: number; total_edges: number; }
interface FullGraphView { nodes: GNode[]; edges: GEdge[]; stats: GraphViewStats; }
interface GraphSubgraph { center: string; nodes: GNode[]; edges: GEdge[]; }

const KIND_COLORS: Record<string, string> = { component: "#1890ff", vulnerability: "#ff4d4f", license: "#52c41a", supplier: "#722ed1", pipeline: "#fa8c16", artifact: "#13c2c2" };
const KIND_BG: Record<string, string> = { component: "#1890ff15", vulnerability: "#ff4d4f15", license: "#52c41a15", supplier: "#722ed115", pipeline: "#fa8c1615", artifact: "#13c2c215" };

// ─────────────────── Custom Node ───────────────────

function SbomNode({ data, selected }: NodeProps) {
    const d = data as { label: string; icon: string; kind: string; color: string; details: Record<string, string>; onExpand: (id: string) => void; nodeId: string };
    return (
        <div style={{
            padding: "8px 14px", borderRadius: 10, border: `2px solid ${selected ? "#fff" : d.color}`,
            background: KIND_BG[d.kind] || "#16162a", minWidth: 120, fontFamily: "Inter, sans-serif",
            boxShadow: selected ? `0 0 12px ${d.color}44` : "0 2px 8px #00000033",
            transition: "all 0.15s",
        }}>
            <Handle type="target" position={Position.Top} style={{ background: d.color, width: 6, height: 6 }} />
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                <span style={{ fontSize: 16 }}>{d.icon}</span>
                <span style={{ fontSize: 12, fontWeight: 700, color: "#e0e0e0", maxWidth: 130, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{d.label}</span>
            </div>
            <div style={{ fontSize: 9, color: d.color, textTransform: "uppercase", letterSpacing: 1, marginBottom: 3 }}>{d.kind}</div>
            {Object.entries(d.details).slice(0, 3).map(([k, v]) => (
                <div key={k} style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: "#888", gap: 8 }}>
                    <span>{k}</span><span style={{ color: "#b8b8cc", fontFamily: "monospace" }}>{String(v).slice(0, 20)}</span>
                </div>
            ))}
            <div style={{ marginTop: 4, textAlign: "center" }}>
                <button onClick={(e) => { e.stopPropagation(); d.onExpand(d.nodeId); }}
                    style={{ fontSize: 9, padding: "2px 8px", border: `1px solid ${d.color}`, borderRadius: 6, background: "transparent", color: d.color, cursor: "pointer" }}>
                    🔍 expand
                </button>
            </div>
            <Handle type="source" position={Position.Bottom} style={{ background: d.color, width: 6, height: 6 }} />
        </div>
    );
}

const nodeTypes = { sbomNode: SbomNode };

// ─────────────────── Layout ───────────────────

function autoLayout(gNodes: GNode[]): Node[] {
    const groups: Record<string, GNode[]> = {};
    gNodes.forEach(n => { (groups[n.kind] = groups[n.kind] || []).push(n); });

    const kindOrder = ["pipeline", "artifact", "component", "vulnerability", "license", "supplier"];
    const nodes: Node[] = [];
    let yOffset = 0;

    for (const kind of kindOrder) {
        const grp = groups[kind] || [];
        const cols = Math.max(Math.ceil(Math.sqrt(grp.length)), 1);
        grp.forEach((n, i) => {
            const col = i % cols;
            const row = Math.floor(i / cols);
            nodes.push({
                id: n.id,
                type: "sbomNode",
                position: { x: col * 200 + 50, y: yOffset + row * 140 },
                data: { ...n, nodeId: n.id, onExpand: () => { } },
            });
        });
        yOffset += (Math.ceil(grp.length / cols)) * 140 + 60;
    }
    return nodes;
}

function toFlowEdges(gEdges: GEdge[]): Edge[] {
    const seen = new Set<string>();
    return gEdges.filter(e => {
        const key = `${e.from}-${e.to}-${e.kind}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    }).map((e, i) => ({
        id: `e-${i}`,
        source: e.from,
        target: e.to,
        label: e.label !== "→" ? e.label : undefined,
        type: "default",
        animated: e.kind === "has_vuln",
        style: { stroke: e.color || "#555", strokeDasharray: e.dashed ? "5,5" : undefined, strokeWidth: e.kind === "depends_on" ? 2 : 1 },
        labelStyle: { fontSize: 9, fill: "#666" },
        markerEnd: { type: MarkerType.ArrowClosed, color: e.color || "#555", width: 14, height: 14 },
    }));
}

// ─────────────────── Panel ───────────────────

export default function GraphExplorerPanel() {
    const [sbomPath, setSbomPath] = useState("");
    const [fullStats, setFullStats] = useState<GraphViewStats | null>(null);
    const [rfNodes, setRfNodes, onNodesChange] = useNodesState<Node>([]);
    const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState<Edge>([]);
    const [selected, setSelected] = useState<GNode | null>(null);
    const [loading, setLoading] = useState(false);
    const [filterKind, setFilterKind] = useState("all");
    const [allGNodes, setAllGNodes] = useState<GNode[]>([]);
    const [allGEdges, setAllGEdges] = useState<GEdge[]>([]);
    const [traversalKind, setTraversalKind] = useState("component");
    const [expandEdge, setExpandEdge] = useState("depends_on");
    const [traversalDepth, setTraversalDepth] = useState(2);

    const expandNode = useCallback(async (nodeId: string) => {
        if (!sbomPath.trim()) return;
        try {
            const sub = await invoke<GraphSubgraph>("expand_graph_node", { sbomPath, nodeId });
            const existingIds = new Set(rfNodes.map((n: Node) => n.id));
            const center = rfNodes.find((n: Node) => n.id === nodeId);
            const cx = center?.position?.x || 400, cy = center?.position?.y || 300;
            const newGNodes = sub.nodes.filter((n: GNode) => !existingIds.has(n.id));
            const newFlowNodes: Node[] = newGNodes.map((n, i) => ({
                id: n.id, type: "sbomNode",
                position: { x: cx + Math.cos((i / Math.max(newGNodes.length, 1)) * Math.PI * 2) * 200, y: cy + Math.sin((i / Math.max(newGNodes.length, 1)) * Math.PI * 2) * 200 },
                data: { ...n, nodeId: n.id, onExpand: expandNode },
            }));
            setRfNodes((prev: Node[]) => [...prev, ...newFlowNodes]);
            setAllGNodes(prev => [...prev, ...newGNodes]);
            const existingEdgeKeys = new Set(rfEdges.map((e: Edge) => `${e.source}-${e.target}`));
            const newEdges = sub.edges.filter(e => !existingEdgeKeys.has(`${e.from}-${e.to}`));
            setRfEdges((prev: Edge[]) => [...prev, ...toFlowEdges(newEdges).map((e: Edge, i: number) => ({ ...e, id: `exp-${Date.now()}-${i}` }))]);
            setAllGEdges((prev: GEdge[]) => [...prev, ...newEdges]);
        } catch (e) { console.error(e); }
    }, [sbomPath, rfNodes, rfEdges, setRfNodes, setRfEdges]);

    const loadGraph = useCallback(async () => {
        if (!sbomPath.trim()) return;
        setLoading(true);
        try {
            const g = await invoke<FullGraphView>("get_full_graph", { sbomPath });
            setFullStats(g.stats);
            setAllGNodes(g.nodes);
            setAllGEdges(g.edges);
            const layoutd = autoLayout(g.nodes);
            // Inject expandNode callback
            const withCallback = layoutd.map((n: Node) => ({ ...n, data: { ...n.data, onExpand: expandNode } }));
            setRfNodes(withCallback);
            setRfEdges(toFlowEdges(g.edges));
            setSelected(null);
        } catch (e) { alert(String(e)); }
        setLoading(false);
    }, [sbomPath, expandNode, setRfNodes, setRfEdges]);

    const runTraversal = useCallback(async () => {
        if (!sbomPath.trim()) return;
        try {
            const result = await invoke<{ nodes: GNode[]; edges: GEdge[] }>("traverse_graph", {
                sbomPath,
                query: { start_kind: traversalKind, filter_field: null, filter_op: null, filter_value: null, expand_kinds: [expandEdge], depth: traversalDepth, limit: 20 },
            });
            setAllGNodes(result.nodes);
            setAllGEdges(result.edges);
            const layoutd = autoLayout(result.nodes).map((n: Node) => ({ ...n, data: { ...n.data, onExpand: expandNode } }));
            setRfNodes(layoutd);
            setRfEdges(toFlowEdges(result.edges));
        } catch (e) { alert(String(e)); }
    }, [sbomPath, traversalKind, expandEdge, traversalDepth, expandNode, setRfNodes, setRfEdges]);

    const onNodeClick = useCallback((_: unknown, node: Node) => {
        const gn = allGNodes.find(n => n.id === node.id);
        if (gn) setSelected(gn);
    }, [allGNodes]);

    // Filter
    const filteredNodeIds = useMemo(() => {
        if (filterKind === "all") return null;
        return new Set(allGNodes.filter(n => n.kind === filterKind).map(n => n.id));
    }, [allGNodes, filterKind]);

    const displayNodes = filteredNodeIds ? rfNodes.filter((n: Node) => filteredNodeIds.has(n.id)) : rfNodes;
    const displayNodeIds = new Set(displayNodes.map((n: Node) => n.id));
    const displayEdges = rfEdges.filter((e: Edge) => displayNodeIds.has(e.source) && displayNodeIds.has(e.target));

    const s = fullStats;

    return (
        <div style={{ padding: "24px", maxWidth: 1600, margin: "0 auto" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
                <h2 style={{ margin: 0 }}>🌐 SBOM Graph Explorer</h2>
                {s && <span className="ge2-badge">{s.total_nodes} nodes · {s.total_edges} edges</span>}
            </div>

            <div className="ge2-form">
                <input className="ge2-inp" style={{ flex: 1 }} value={sbomPath} onChange={e => setSbomPath(e.target.value)} placeholder="Path to CycloneDX SBOM JSON" onKeyDown={e => e.key === "Enter" && loadGraph()} />
                <button onClick={loadGraph} disabled={loading} className="ge2-btn">{loading ? "⏳" : "🌐"} Load Graph</button>
            </div>

            {s && (
                <div className="ge2-controls">
                    <div className="ge2-filter-row">
                        <span className="ge2-lbl">Filter:</span>
                        {["all", "component", "vulnerability", "license", "supplier", "pipeline", "artifact"].map(k => (
                            <button key={k} className={`ge2-filt ${filterKind === k ? "active" : ""}`} onClick={() => setFilterKind(k)}
                                style={k !== "all" ? { borderColor: KIND_COLORS[k] || "#666", color: filterKind === k ? KIND_COLORS[k] : undefined } : {}}>
                                {k === "all" ? `All (${s.total_nodes})` : `${k} (${allGNodes.filter(n => n.kind === k).length})`}
                            </button>
                        ))}
                    </div>
                    <div className="ge2-filter-row" style={{ marginTop: 6, paddingTop: 6, borderTop: "1px solid #2a2a4a" }}>
                        <span className="ge2-lbl">Traverse:</span>
                        <select className="ge2-sel" value={traversalKind} onChange={e => setTraversalKind(e.target.value)}>
                            {["component", "vulnerability", "license", "supplier"].map(k => <option key={k}>{k}</option>)}
                        </select>
                        <span style={{ color: "#666", fontSize: 11 }}>→</span>
                        <select className="ge2-sel" value={expandEdge} onChange={e => setExpandEdge(e.target.value)}>
                            {["depends_on", "has_vuln", "licensed_by", "supplied_by", "produces", "pipeline"].map(k => <option key={k}>{k}</option>)}
                        </select>
                        <span style={{ color: "#666", fontSize: 11 }}>depth</span>
                        <select className="ge2-sel" value={traversalDepth} onChange={e => setTraversalDepth(+e.target.value)}>
                            {[1, 2, 3, 4].map(d => <option key={d} value={d}>{d}</option>)}
                        </select>
                        <button onClick={runTraversal} className="ge2-btn-sm">▶ Traverse</button>
                        <button onClick={loadGraph} className="ge2-btn-sm" style={{ opacity: 0.6 }}>↻ Reset</button>
                    </div>
                </div>
            )}

            {/* React Flow graph */}
            {displayNodes.length > 0 && (
                <div style={{ display: "flex", gap: 12 }}>
                    <div style={{ flex: 1, height: 700, border: "1px solid #2a2a4a", borderRadius: 12, overflow: "hidden" }}>
                        <ReactFlow
                            nodes={displayNodes}
                            edges={displayEdges}
                            onNodesChange={onNodesChange}
                            onEdgesChange={onEdgesChange}
                            onNodeClick={onNodeClick}
                            nodeTypes={nodeTypes}
                            fitView
                            minZoom={0.1}
                            maxZoom={4}
                            proOptions={{ hideAttribution: true }}
                            style={{ background: "#0a0a16" }}
                        >
                            <Background color="#1a1a30" gap={24} size={1} />
                            <Controls style={{ background: "#16162a", borderColor: "#2a2a4a", borderRadius: 8 }} />
                            <MiniMap
                                nodeColor={(n: Node) => {
                                    const d = n.data as { kind?: string } | undefined;
                                    return KIND_COLORS[d?.kind || ""] || "#666";
                                }}
                                maskColor="#0a0a1699"
                                style={{ background: "#16162a", borderRadius: 8, border: "1px solid #2a2a4a" }}
                            />
                        </ReactFlow>
                    </div>

                    {/* Detail panel */}
                    <div className="ge2-detail" style={{ width: 280 }}>
                        {selected ? (
                            <>
                                <div className="ge2-det-hdr" style={{ borderColor: selected.color }}>
                                    <span style={{ fontSize: 24 }}>{selected.icon}</span>
                                    <div><div className="ge2-det-name">{selected.label}</div><div style={{ fontSize: 10, color: selected.color, textTransform: "uppercase" }}>{selected.kind}</div></div>
                                </div>
                                <div style={{ fontSize: 9, color: "#555", marginBottom: 8, wordBreak: "break-all" }}>ID: <code style={{ color: "#888" }}>{selected.id}</code></div>
                                {Object.entries(selected.details).map(([k, v]) => (
                                    <div key={k} className="ge2-det-row"><span style={{ color: "#8c8c8c" }}>{k}</span><span style={{ color: "#e0e0e0", fontFamily: "monospace", textAlign: "right", maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis" }}>{v}</span></div>
                                ))}
                                <button className="ge2-expand-btn" onClick={() => expandNode(selected.id)}>🔍 Expand neighbors</button>
                                <div style={{ marginTop: 8 }}>
                                    <div style={{ fontSize: 10, color: "#8c8c8c", textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>Connections</div>
                                    {allGEdges.filter(e => e.from === selected.id || e.to === selected.id).slice(0, 15).map((e, i) => (
                                        <div key={i} className="ge2-det-edge" onClick={() => { const tgt = e.from === selected.id ? e.to : e.from; const n = allGNodes.find(n2 => n2.id === tgt); if (n) setSelected(n); }}>
                                            <span style={{ color: e.color || "#666" }}>{e.kind}</span>
                                            <span style={{ color: "#888" }}>→ {(e.from === selected.id ? e.to : e.from).split('/').pop()?.split('@')[0]}</span>
                                        </div>
                                    ))}
                                </div>
                            </>
                        ) : (
                            <div style={{ textAlign: "center", padding: "40px 10px", color: "#555", fontSize: 12, lineHeight: 1.6 }}>Click a node to inspect<br />Use expand button on nodes<br />Scroll to zoom · Drag to pan</div>
                        )}
                    </div>
                </div>
            )}

            {!fullStats && !loading && (
                <div style={{ textAlign: "center", padding: "60px 20px", color: "#666" }}>
                    <div style={{ fontSize: 48 }}>🌐</div>
                    <div style={{ fontSize: 16, margin: "8px 0" }}>SBOM Graph Explorer</div>
                    <div style={{ color: "#8c8c8c", maxWidth: 520, lineHeight: 1.6, margin: "0 auto" }}>
                        Interactive <strong>React Flow</strong> graph navigation across all DevSecOps layers:<br />
                        <strong>📦 Components</strong> · <strong>🔴 Vulns</strong> · <strong>📜 Licenses</strong> · <strong>🏢 Suppliers</strong> · <strong>⚙️ Pipeline</strong> · <strong>📄 Artifacts</strong><br /><br />
                        Click nodes to inspect · Expand to discover · Scroll to zoom · Drag to pan
                    </div>
                </div>
            )}

            <style>{`
        .ge2-badge{font-size:10px;color:#1890ff;background:#1890ff18;padding:3px 10px;border-radius:12px}
        .ge2-form{display:flex;gap:8px;padding:12px;background:#16162a;border:1px solid #2a2a4a;border-radius:12px;margin-bottom:10px}
        .ge2-inp{padding:8px 12px;background:#0e0e1a;border:1px solid #333;border-radius:8px;color:#e0e0e0;font-family:monospace;font-size:13px;outline:none}
        .ge2-inp:focus{border-color:#1890ff}
        .ge2-btn{padding:8px 18px;border-radius:8px;border:1px solid #1890ff;background:#1890ff22;color:#69c0ff;cursor:pointer;font-size:13px;font-weight:600;white-space:nowrap}
        .ge2-btn:disabled{opacity:.5}.ge2-btn:hover{background:#1890ff44}
        .ge2-controls{padding:8px 12px;background:#16162a;border:1px solid #2a2a4a;border-radius:10px;margin-bottom:10px}
        .ge2-filter-row{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
        .ge2-lbl{font-size:10px;color:#8c8c8c;text-transform:uppercase;letter-spacing:1px;width:55px}
        .ge2-filt{padding:3px 10px;border:1px solid #333;border-radius:6px;background:transparent;color:#8c8c8c;cursor:pointer;font-size:10px;transition:all .15s}
        .ge2-filt:hover{color:#e0e0e0}.ge2-filt.active{color:#e0e0e0;background:#ffffff0a}
        .ge2-sel{padding:3px 6px;background:#0e0e1a;border:1px solid #333;border-radius:6px;color:#e0e0e0;font-size:11px;font-family:monospace}
        .ge2-btn-sm{padding:3px 10px;border:1px solid #1890ff;border-radius:6px;background:#1890ff22;color:#69c0ff;cursor:pointer;font-size:11px}
        .ge2-detail{background:#16162a;border:1px solid #2a2a4a;border-radius:12px;padding:14px;overflow-y:auto;max-height:700px}
        .ge2-det-hdr{display:flex;gap:10px;align-items:center;padding-bottom:10px;border-bottom:2px solid;margin-bottom:8px}
        .ge2-det-name{font-size:14px;font-weight:700;color:#e0e0e0}
        .ge2-det-row{display:flex;justify-content:space-between;padding:3px 0;font-size:11px;border-bottom:1px solid #1a1a30}
        .ge2-expand-btn{width:100%;margin:10px 0;padding:6px;border:1px solid #1890ff;border-radius:8px;background:#1890ff22;color:#69c0ff;cursor:pointer;font-size:12px}
        .ge2-expand-btn:hover{background:#1890ff44}
        .ge2-det-edge{padding:3px 0;font-size:10px;cursor:pointer;display:flex;gap:6px;border-bottom:1px solid #1a1a30}
        .ge2-det-edge:hover{background:#ffffff06}
        .react-flow__node{cursor:pointer!important}
        .react-flow__controls button{background:#16162a!important;border-color:#2a2a4a!important;color:#e0e0e0!important}
        .react-flow__controls button:hover{background:#2a2a4a!important}
      `}</style>
        </div>
    );
}
