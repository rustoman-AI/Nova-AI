import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
    ReactFlow, Background, Controls, MiniMap,
    useNodesState, useEdgesState, MarkerType,
    type Node, type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

interface ChainNode { id: string; label: string; kind: string; icon: string; color: string; details: Record<string, string>; }
interface ChainEdge { from: string; to: string; label: string; }
interface AstSummary { total_files: number; total_lines: number; languages: Record<string, number>; build_systems: string[]; declared_deps: number; internal_imports: number; external_imports: number; entry_points: string[]; top_importers: [string, number][]; }
interface BuildSummary { targets: number; resolved_deps: number; build_steps: number; outputs: number; build_commands: string[]; }
interface ChainStats { total_chain_nodes: number; total_chain_edges: number; graphs_connected: number; source_to_trust_depth: number; }
interface SupplyChain { ast: AstSummary; build: BuildSummary; chain_nodes: ChainNode[]; chain_edges: ChainEdge[]; chain_stats: ChainStats; }

const KIND_C: Record<string, string> = { ast: "#eb2f96", build: "#fa8c16", execution: "#1890ff", artifact: "#13c2c2", sbom: "#52c41a", trust: "#722ed1" };
const LAYER_Y: Record<string, number> = { ast: 0, build: 200, execution: 400, artifact: 600, sbom: 800, trust: 1000 };

function chainToFlow(nodes: ChainNode[], edges: ChainEdge[]): { flowNodes: Node[]; flowEdges: Edge[] } {
    const layers: Record<string, ChainNode[]> = {};
    nodes.forEach(n => { (layers[n.kind] = layers[n.kind] || []).push(n); });

    const flowNodes: Node[] = nodes.map(n => {
        const layerNodes = layers[n.kind] || [];
        const idx = layerNodes.indexOf(n);
        const total = layerNodes.length;
        const x = (idx - (total - 1) / 2) * 200 + 500;
        return {
            id: n.id,
            position: { x, y: LAYER_Y[n.kind] ?? 0 },
            data: { label: `${n.icon} ${n.label}`, kind: n.kind, details: n.details },
            style: {
                background: `${n.color}15`, border: `2px solid ${n.color}`, borderRadius: 10,
                padding: "8px 14px", fontSize: 11, color: "#e0e0e0", minWidth: 120, textAlign: "center" as const,
            },
        };
    });

    const seen = new Set<string>();
    const flowEdges: Edge[] = edges.filter(e => {
        const k = `${e.from}-${e.to}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
    }).map((e, i) => ({
        id: `ce-${i}`, source: e.from, target: e.to,
        label: e.label !== "→" ? e.label : undefined,
        style: { stroke: "#555", strokeWidth: 1.5 },
        labelStyle: { fontSize: 9, fill: "#888" },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#555", width: 12, height: 12 },
        animated: e.label === "produces" || e.label === "triggers",
    }));

    return { flowNodes, flowEdges };
}

export default function SupplyChainPanel() {
    const [rootDir, setRootDir] = useState("");
    const [sbomPath, setSbomPath] = useState("");
    const [result, setResult] = useState<SupplyChain | null>(null);
    const [loading, setLoading] = useState(false);
    const [rfNodes, setRfNodes, onNodesChange] = useNodesState<Node>([]);
    const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState<Edge>([]);
    const [tab, setTab] = useState<"chain" | "ast" | "build">("chain");

    const scan = useCallback(async () => {
        if (!rootDir.trim()) return;
        setLoading(true);
        try {
            const r = await invoke<SupplyChain>("scan_supply_chain", { rootDir, sbomPath: sbomPath.trim() || null });
            setResult(r);
            const { flowNodes, flowEdges } = chainToFlow(r.chain_nodes, r.chain_edges);
            setRfNodes(flowNodes);
            setRfEdges(flowEdges);
        } catch (e) { alert(String(e)); }
        setLoading(false);
    }, [rootDir, sbomPath, setRfNodes, setRfEdges]);

    const r = result;
    return (
        <div style={{ padding: "24px", maxWidth: 1600, margin: "0 auto" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
                <h2 style={{ margin: 0 }}>🔗 Supply Chain Graph</h2>
                {r && <span className="sc-badge">{r.chain_stats.graphs_connected} graphs · {r.chain_stats.total_chain_nodes} nodes</span>}
            </div>

            <div className="sc-form">
                <input className="sc-inp" style={{ flex: 1 }} value={rootDir} onChange={e => setRootDir(e.target.value)} placeholder="Project root directory" onKeyDown={e => e.key === "Enter" && scan()} />
                <input className="sc-inp" style={{ width: 300 }} value={sbomPath} onChange={e => setSbomPath(e.target.value)} placeholder="SBOM path (optional)" />
                <button onClick={scan} disabled={loading} className="sc-btn">{loading ? "⏳" : "🔗"} Scan</button>
            </div>

            {r && (
                <>
                    {/* Layer legend */}
                    <div className="sc-legend">
                        {(["ast", "build", "execution", "artifact", "sbom", "trust"] as const).map((k, i) => (
                            <div key={k} className="sc-legend-item">
                                <span className="sc-legend-dot" style={{ background: KIND_C[k] }} />
                                <span className="sc-legend-label">{["📝 ASTGraph", "🔨 BuildGraph", "⚙️ ExecutionGraph", "📄 ArtifactGraph", "📦 SBOMGraph", "🛡️ TrustGraph"][i]}</span>
                                {i < 5 && <span className="sc-legend-arrow">↓</span>}
                            </div>
                        ))}
                    </div>

                    {/* Tabs */}
                    <div className="sc-tabs">{(["chain", "ast", "build"] as const).map(t => (
                        <button key={t} className={`sc-tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
                            {{ chain: "🔗 Chain Graph", ast: "📝 AST Analysis", build: "🔨 Build System" }[t]}
                        </button>
                    ))}</div>

                    {/* Chain Graph */}
                    {tab === "chain" && (
                        <div style={{ height: 700, border: "1px solid #2a2a4a", borderRadius: 12, overflow: "hidden" }}>
                            <ReactFlow nodes={rfNodes} edges={rfEdges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
                                fitView minZoom={0.2} maxZoom={3} proOptions={{ hideAttribution: true }} style={{ background: "#0a0a16" }}>
                                <Background color="#1a1a30" gap={24} size={1} />
                                <Controls style={{ background: "#16162a", borderColor: "#2a2a4a", borderRadius: 8 }} />
                                <MiniMap nodeColor={(n: Node) => { const d = n.data as { kind?: string }; return KIND_C[d?.kind || ""] || "#666"; }} maskColor="#0a0a1699" style={{ background: "#16162a", borderRadius: 8, border: "1px solid #2a2a4a" }} />
                            </ReactFlow>
                        </div>
                    )}

                    {/* AST Analysis */}
                    {tab === "ast" && (
                        <div className="sc-panels">
                            <div className="sc-panel">
                                <div className="sc-panel-title">📊 Statistics</div>
                                <div className="sc-kv"><span>Files</span><span>{r.ast.total_files}</span></div>
                                <div className="sc-kv"><span>Lines</span><span>{r.ast.total_lines.toLocaleString()}</span></div>
                                <div className="sc-kv"><span>Declared deps</span><span>{r.ast.declared_deps}</span></div>
                                <div className="sc-kv"><span>Internal imports</span><span>{r.ast.internal_imports}</span></div>
                                <div className="sc-kv"><span>External imports</span><span>{r.ast.external_imports}</span></div>
                            </div>
                            <div className="sc-panel">
                                <div className="sc-panel-title">🌐 Languages</div>
                                {Object.entries(r.ast.languages).sort((a, b) => b[1] - a[1]).map(([lang, count]) => (
                                    <div key={lang} className="sc-lang-bar">
                                        <span className="sc-lang-name">{lang}</span>
                                        <div className="sc-bar"><div className="sc-bar-fill" style={{ width: `${(count / r.ast.total_files) * 100}%`, background: KIND_C.ast }} /></div>
                                        <span className="sc-lang-count">{count}</span>
                                    </div>
                                ))}
                            </div>
                            <div className="sc-panel">
                                <div className="sc-panel-title">🚪 Entry Points</div>
                                {r.ast.entry_points.length === 0 && <div className="sc-empty-sm">No entry points detected</div>}
                                {r.ast.entry_points.map((ep, i) => <div key={i} className="sc-entry"><code>{ep}</code></div>)}
                            </div>
                            <div className="sc-panel">
                                <div className="sc-panel-title">📈 Top Importers</div>
                                {r.ast.top_importers.map(([file, count], i) => (
                                    <div key={i} className="sc-kv"><code style={{ fontSize: 10 }}>{file.split('/').pop()}</code><span>{count} imports</span></div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Build System */}
                    {tab === "build" && (
                        <div className="sc-panels">
                            <div className="sc-panel">
                                <div className="sc-panel-title">🎯 Targets</div>
                                <div className="sc-kv"><span>Build targets</span><span>{r.build.targets}</span></div>
                                <div className="sc-kv"><span>Resolved deps</span><span>{r.build.resolved_deps}</span></div>
                                <div className="sc-kv"><span>Build steps</span><span>{r.build.build_steps}</span></div>
                                <div className="sc-kv"><span>Outputs</span><span>{r.build.outputs}</span></div>
                            </div>
                            <div className="sc-panel">
                                <div className="sc-panel-title">🔧 Build Commands</div>
                                {r.build.build_commands.map((cmd, i) => (
                                    <div key={i} className="sc-cmd"><code>{cmd}</code></div>
                                ))}
                            </div>
                            <div className="sc-panel">
                                <div className="sc-panel-title">📦 Build Systems</div>
                                {r.ast.build_systems.map((bs, i) => (
                                    <div key={i} className="sc-bs"><span style={{ color: "#fa8c16" }}>{bs}</span></div>
                                ))}
                            </div>
                        </div>
                    )}
                </>
            )}

            {!r && !loading && (
                <div className="sc-empty">
                    <div style={{ fontSize: 48 }}>🔗</div>
                    <div style={{ fontSize: 16, margin: "8px 0" }}>End-to-End Supply Chain Graph</div>
                    <div style={{ color: "#8c8c8c", maxWidth: 530, lineHeight: 1.6, margin: "0 auto" }}>
                        Scans project source to build the <strong>complete supply chain</strong>:<br /><br />
                        <strong>📝 ASTGraph</strong> → <strong>🔨 BuildGraph</strong> → <strong>⚙️ ExecutionGraph</strong> →
                        <strong>📄 ArtifactGraph</strong> → <strong>📦 SBOMGraph</strong> → <strong>🛡️ TrustGraph</strong><br /><br />
                        6 graphs · source code → trust score · 6 languages · 9 build systems
                    </div>
                </div>
            )}

            <style>{`
        .sc-badge{font-size:10px;color:#eb2f96;background:#eb2f9618;padding:3px 10px;border-radius:12px}
        .sc-form{display:flex;gap:8px;padding:12px;background:#16162a;border:1px solid #2a2a4a;border-radius:12px;margin-bottom:10px}
        .sc-inp{padding:8px 12px;background:#0e0e1a;border:1px solid #333;border-radius:8px;color:#e0e0e0;font-family:monospace;font-size:13px;outline:none}
        .sc-inp:focus{border-color:#eb2f96}
        .sc-btn{padding:8px 18px;border-radius:8px;border:1px solid #eb2f96;background:#eb2f9622;color:#ff85c0;cursor:pointer;font-size:13px;font-weight:600;white-space:nowrap}
        .sc-btn:disabled{opacity:.5}.sc-btn:hover{background:#eb2f9644}
        .sc-legend{display:flex;align-items:center;gap:4px;padding:8px 14px;background:#16162a;border:1px solid #2a2a4a;border-radius:10px;margin-bottom:10px;flex-wrap:wrap}
        .sc-legend-item{display:flex;align-items:center;gap:4px}
        .sc-legend-dot{width:8px;height:8px;border-radius:50%}
        .sc-legend-label{font-size:10px;color:#b8b8cc}
        .sc-legend-arrow{color:#444;font-size:12px;margin:0 4px}
        .sc-tabs{display:flex;gap:4px;margin-bottom:10px}
        .sc-tab{padding:8px 14px;border:1px solid #2a2a4a;border-radius:8px 8px 0 0;background:transparent;color:#8c8c8c;cursor:pointer;font-size:12px;transition:all .15s}
        .sc-tab:hover{color:#e0e0e0}.sc-tab.active{background:#16162a;color:#e0e0e0;border-bottom-color:#16162a}
        .sc-panels{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px}
        .sc-panel{padding:14px;background:#16162a;border:1px solid #2a2a4a;border-radius:10px}
        .sc-panel-title{font-size:12px;font-weight:700;color:#e0e0e0;margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid #2a2a4a}
        .sc-kv{display:flex;justify-content:space-between;padding:3px 0;font-size:11px;border-bottom:1px solid #1a1a30}
        .sc-kv span:first-child{color:#8c8c8c}.sc-kv span:last-child{color:#e0e0e0;font-family:monospace}
        .sc-lang-bar{display:flex;align-items:center;gap:8px;padding:3px 0}
        .sc-lang-name{width:80px;font-size:11px;color:#b8b8cc}
        .sc-bar{flex:1;height:6px;background:#0e0e1a;border-radius:3px;overflow:hidden}
        .sc-bar-fill{height:100%;border-radius:3px;transition:width .3s}
        .sc-lang-count{font-size:10px;color:#666;width:30px;text-align:right}
        .sc-entry{padding:3px 0;font-size:11px;border-bottom:1px solid #1a1a30}
        .sc-entry code{color:#eb2f96}
        .sc-cmd{padding:4px 0;font-size:11px;border-bottom:1px solid #1a1a30}
        .sc-cmd code{color:#fa8c16;background:#fa8c1610;padding:2px 6px;border-radius:4px}
        .sc-bs{padding:3px 0;font-size:11px}
        .sc-empty{text-align:center;padding:60px 20px;color:#666}
        .sc-empty-sm{text-align:center;padding:10px;color:#555;font-size:11px}
        .react-flow__controls button{background:#16162a!important;border-color:#2a2a4a!important;color:#e0e0e0!important}
      `}</style>
        </div>
    );
}
