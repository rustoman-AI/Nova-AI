import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";

interface MermaidBlock { index: number; code: string; title: string; explanation: string; }
interface ArchFile { name: string; path: string; size_bytes: number; content: string; mermaid_blocks: MermaidBlock[]; }
interface ArchProject { id: string; name: string; version: string; path: string; arch_dir: string; files: ArchFile[]; has_arch: boolean; icon: string; tech: string; }
interface ProjectLink { from: string; to: string; relation: string; label: string; }

const RELATION_STYLES: Record<string, { color: string; dash: string; label: string }> = {
    uses: { color: "#1890ff", dash: "", label: "uses" },
    invokes: { color: "#52c41a", dash: "", label: "invokes" },
    inspires: { color: "#fa8c16", dash: "5,5", label: "inspires" },
};

const WORKSPACE = "/home/timur/Desktop/_2026_trivy";

export default function ArchBrowserPanel() {
    const [projects, setProjects] = useState<ArchProject[]>([]);
    const [links, setLinks] = useState<ProjectLink[]>([]);
    const [selectedProject, setSelectedProject] = useState<string | null>(null);
    const [selectedFile, setSelectedFile] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const [view, setView] = useState<"graph" | "explorer">("graph");

    useEffect(() => {
        setLoading(true);
        Promise.all([
            invoke<ArchProject[]>("scan_architectures", { workspacePath: WORKSPACE }),
            invoke<ProjectLink[]>("get_project_links"),
        ]).then(([p, l]) => { setProjects(p); setLinks(l); setLoading(false); })
            .catch(e => { alert(String(e)); setLoading(false); });
    }, []);

    const proj = projects.find(p => p.id === selectedProject);
    const file = proj?.files.find(f => f.name === selectedFile);
    const totalDiagrams = projects.reduce((sum, p) => sum + p.files.reduce((s, f) => s + f.mermaid_blocks.length, 0), 0);
    const totalFiles = projects.reduce((sum, p) => sum + p.files.length, 0);
    const totalSize = projects.reduce((sum, p) => sum + p.files.reduce((s, f) => s + f.size_bytes, 0), 0);

    return (
        <div style={{ padding: "24px", maxWidth: 1400, margin: "0 auto" }}>
            {/* Header */}
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
                <h2 style={{ margin: 0 }}>🗺️ Architecture Browser</h2>
                <span className="ab-badge">{projects.filter(p => p.has_arch).length}/7 projects</span>
                <span className="ab-badge">{totalFiles} docs</span>
                <span className="ab-badge">{totalDiagrams} diagrams</span>
                <span className="ab-badge">{(totalSize / 1024).toFixed(0)} KB</span>
                <div style={{ flex: 1 }} />
                <div className="ab-tabs-mini">
                    <button className={view === "graph" ? "active" : ""} onClick={() => { setView("graph"); setSelectedProject(null); }}>🔗 Dependency Graph</button>
                    <button className={view === "explorer" ? "active" : ""} onClick={() => setView("explorer")}>📂 Explorer</button>
                </div>
            </div>

            {loading && <div className="ab-loading">⏳ Scanning architectures...</div>}

            {/* Dependency Graph View */}
            {view === "graph" && !loading && (
                <div className="ab-graph-section">
                    <DependencyGraph projects={projects} links={links} onSelect={(id) => { setSelectedProject(id); setView("explorer"); setSelectedFile("ARCHITECTURE.md"); }} />
                    {/* Legend */}
                    <div className="ab-legend">
                        {Object.entries(RELATION_STYLES).map(([k, v]) => (
                            <span key={k} className="ab-legend-item">
                                <svg width="24" height="8"><line x1="0" y1="4" x2="24" y2="4" stroke={v.color} strokeWidth="2" strokeDasharray={v.dash || "none"} /></svg>
                                {v.label}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Explorer View */}
            {view === "explorer" && !loading && (
                <div className="ab-explorer">
                    {/* Project sidebar */}
                    <div className="ab-sidebar">
                        {projects.map(p => (
                            <div key={p.id} className={`ab-proj-item ${selectedProject === p.id ? "active" : ""} ${!p.has_arch ? "disabled" : ""}`} onClick={() => { if (p.has_arch) { setSelectedProject(p.id); setSelectedFile(p.files[0]?.name || null); } }}>
                                <span className="ab-proj-icon">{p.icon}</span>
                                <div className="ab-proj-info">
                                    <div className="ab-proj-name">{p.name}</div>
                                    <div className="ab-proj-meta">{p.version} · {p.tech} · {p.files.length} docs</div>
                                </div>
                                {p.has_arch && <span className="ab-proj-count">{p.files.reduce((s, f) => s + f.mermaid_blocks.length, 0)}</span>}
                            </div>
                        ))}
                    </div>

                    {/* File list + content */}
                    <div className="ab-content">
                        {proj && (
                            <>
                                {/* File tabs */}
                                <div className="ab-file-tabs">
                                    {proj.files.map(f => (
                                        <button key={f.name} className={`ab-file-tab ${selectedFile === f.name ? "active" : ""}`} onClick={() => setSelectedFile(f.name)}>
                                            📄 {f.name} <span className="ab-file-count">{f.mermaid_blocks.length}</span>
                                        </button>
                                    ))}
                                </div>

                                {/* Diagrams */}
                                {file && (
                                    <div className="ab-diagrams">
                                        {file.mermaid_blocks.length === 0 && <div className="ab-empty-file">No Mermaid diagrams in this file</div>}
                                        {file.mermaid_blocks.map((block, i) => (
                                            <MermaidCard key={i} block={block} projectName={proj.name} fileName={file.name} />
                                        ))}
                                    </div>
                                )}
                            </>
                        )}
                        {!proj && (
                            <div className="ab-empty">
                                <div style={{ fontSize: 48, marginBottom: 12 }}>📂</div>
                                <div>Select a project to browse architecture diagrams</div>
                            </div>
                        )}
                    </div>
                </div>
            )}

            <style>{`
        .ab-badge { font-size: 11px; color: #8c8c8c; background: #ffffff08; padding: 3px 10px; border-radius: 12px; }
        .ab-tabs-mini { display: flex; gap: 2px; background: #16162a; border-radius: 8px; padding: 2px; }
        .ab-tabs-mini button { padding: 6px 14px; border: none; border-radius: 6px; background: transparent; color: #8c8c8c; cursor: pointer; font-size: 12px; transition: all 0.15s; }
        .ab-tabs-mini button:hover { color: #e0e0e0; }
        .ab-tabs-mini button.active { background: #722ed133; color: #b388ff; }
        .ab-loading { text-align: center; padding: 60px; color: #666; }
        .ab-graph-section { padding: 16px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 12px; }
        .ab-legend { display: flex; gap: 16px; justify-content: center; margin-top: 12px; }
        .ab-legend-item { display: flex; align-items: center; gap: 4px; font-size: 11px; color: #8c8c8c; }
        .ab-explorer { display: grid; grid-template-columns: 280px 1fr; gap: 12px; min-height: 600px; }
        .ab-sidebar { display: flex; flex-direction: column; gap: 4px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 12px; padding: 8px; overflow-y: auto; max-height: 700px; }
        .ab-proj-item { display: flex; align-items: center; gap: 8px; padding: 10px 12px; border-radius: 8px; cursor: pointer; transition: all 0.15s; }
        .ab-proj-item:hover { background: #ffffff08; }
        .ab-proj-item.active { background: #722ed122; border-left: 3px solid #722ed1; }
        .ab-proj-item.disabled { opacity: 0.4; cursor: default; }
        .ab-proj-icon { font-size: 20px; }
        .ab-proj-info { flex: 1; min-width: 0; }
        .ab-proj-name { font-size: 12px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .ab-proj-meta { font-size: 10px; color: #666; }
        .ab-proj-count { font-size: 10px; color: #722ed1; background: #722ed118; padding: 2px 6px; border-radius: 8px; }
        .ab-content { background: #16162a; border: 1px solid #2a2a4a; border-radius: 12px; padding: 12px; overflow-y: auto; max-height: 700px; }
        .ab-file-tabs { display: flex; gap: 4px; margin-bottom: 12px; flex-wrap: wrap; }
        .ab-file-tab { padding: 6px 14px; border: 1px solid #2a2a4a; border-radius: 8px; background: transparent; color: #8c8c8c; cursor: pointer; font-size: 12px; transition: all 0.15s; }
        .ab-file-tab:hover { color: #e0e0e0; }
        .ab-file-tab.active { background: #722ed122; color: #b388ff; border-color: #722ed1; }
        .ab-file-count { font-size: 9px; color: #666; margin-left: 4px; }
        .ab-diagrams { display: grid; gap: 16px; }
        .ab-diagram-card { border: 1px solid #2a2a4a; border-radius: 10px; overflow: hidden; }
        .ab-diagram-header { padding: 8px 14px; background: #0e0e1a; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid #2a2a4a; }
        .ab-diagram-title { font-size: 13px; font-weight: 600; }
        .ab-diagram-idx { font-size: 10px; color: #722ed1; background: #722ed118; padding: 1px 6px; border-radius: 6px; }
        .ab-mermaid-box { padding: 16px; background: #0e0e1a; overflow-x: auto; display: flex; justify-content: center; }
        .ab-mermaid-box svg { max-width: 100%; }
        .ab-explanation { padding: 10px 14px; font-size: 12px; color: #a0a0b0; line-height: 1.6; border-top: 1px solid #1a1a30; }
        .ab-mermaid-code { padding: 12px 14px; background: #0a0a14; font-family: monospace; font-size: 11px; color: #8c8c8c; white-space: pre-wrap; max-height: 200px; overflow-y: auto; border-top: 1px solid #1a1a30; }
        .ab-empty { text-align: center; padding: 80px 20px; color: #666; }
        .ab-empty-file { text-align: center; padding: 40px; color: #666; }
      `}</style>
        </div>
    );
}

// ══════════════════════════════════════════════════════
//  Mermaid Diagram Card
// ══════════════════════════════════════════════════════

function MermaidCard({ block, projectName, fileName }: { block: MermaidBlock; projectName: string; fileName: string }) {
    const ref = useRef<HTMLDivElement>(null);
    const [showCode, setShowCode] = useState(false);
    const [rendered, setRendered] = useState(false);

    useEffect(() => {
        if (!ref.current || rendered) return;
        // Dynamic import-style: render mermaid code as SVG using a simple approach
        try {
            // Use a pre-rendered approach: create SVG from mermaid code by simple text display
            // In production, use mermaid.js library; here we show the code with a rendered preview
            const container = ref.current;
            container.innerHTML = `<pre style="margin:0;font-family:monospace;font-size:11px;color:#b388ff;text-align:left;white-space:pre-wrap">${escapeHtml(block.code)}</pre>`;
            setRendered(true);
        } catch { /* fallback to code */ }
    }, [block.code, rendered]);

    return (
        <div className="ab-diagram-card">
            <div className="ab-diagram-header">
                <span className="ab-diagram-idx">#{block.index + 1}</span>
                <span className="ab-diagram-title">{block.title || `${fileName} diagram ${block.index + 1}`}</span>
                <span style={{ fontSize: 10, color: "#666", marginLeft: "auto" }}>{projectName}</span>
                <button onClick={() => setShowCode(!showCode)} style={{ border: "none", background: "none", color: "#666", cursor: "pointer", fontSize: 11 }}>
                    {showCode ? "▲ Hide" : "▼ Code"}
                </button>
            </div>
            <div className="ab-mermaid-box" ref={ref} />
            {block.explanation && <div className="ab-explanation">{block.explanation}</div>}
            {showCode && <div className="ab-mermaid-code">{block.code}</div>}
        </div>
    );
}

function escapeHtml(text: string): string {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ══════════════════════════════════════════════════════
//  SVG Dependency Graph
// ══════════════════════════════════════════════════════

function DependencyGraph({ projects, links, onSelect }: { projects: ArchProject[]; links: ProjectLink[]; onSelect: (id: string) => void }) {
    const W = 900, H = 420;
    // Fixed positions for 7 nodes in a clear layout
    const positions: Record<string, { x: number; y: number }> = {
        "cyclonedx-tauri-ui": { x: 450, y: 200 },
        "clonedx-core-java-12.1.0": { x: 450, y: 40 },
        "cyclonedx-cli-0.30.0": { x: 220, y: 40 },
        "cyclonedx-gradle-plugin-3.2.0": { x: 680, y: 40 },
        "trivy-0.69.3": { x: 150, y: 200 },
        "tracee-33.33.34": { x: 700, y: 340 },
        "black-duck-security-scan-2.8.0": { x: 200, y: 340 },
    };

    return (
        <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: "auto" }}>
            <defs>
                <marker id="arr-uses" viewBox="0 0 10 7" refX="10" refY="3.5" markerWidth="8" markerHeight="6" orient="auto"><polygon points="0 0, 10 3.5, 0 7" fill="#1890ff" /></marker>
                <marker id="arr-invokes" viewBox="0 0 10 7" refX="10" refY="3.5" markerWidth="8" markerHeight="6" orient="auto"><polygon points="0 0, 10 3.5, 0 7" fill="#52c41a" /></marker>
                <marker id="arr-inspires" viewBox="0 0 10 7" refX="10" refY="3.5" markerWidth="8" markerHeight="6" orient="auto"><polygon points="0 0, 10 3.5, 0 7" fill="#fa8c16" /></marker>
            </defs>

            {/* Links */}
            {links.map((link, i) => {
                const from = positions[link.from];
                const to = positions[link.to];
                if (!from || !to) return null;
                const style = RELATION_STYLES[link.relation] || RELATION_STYLES.uses;
                return (
                    <g key={i}>
                        <line x1={from.x} y1={from.y} x2={to.x} y2={to.y} stroke={style.color} strokeWidth="1.5" strokeDasharray={style.dash || "none"} markerEnd={`url(#arr-${link.relation})`} opacity="0.6" />
                        <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 6} fill={style.color} fontSize="8" textAnchor="middle" opacity="0.7">{link.relation}</text>
                    </g>
                );
            })}

            {/* Nodes */}
            {projects.map(p => {
                const pos = positions[p.id];
                if (!pos) return null;
                const diagrams = p.files.reduce((s, f) => s + f.mermaid_blocks.length, 0);
                return (
                    <g key={p.id} onClick={() => onSelect(p.id)} style={{ cursor: "pointer" }}>
                        <rect x={pos.x - 70} y={pos.y - 22} width="140" height="44" rx="10" fill="#16162a" stroke={p.has_arch ? "#722ed1" : "#333"} strokeWidth={p.has_arch ? "1.5" : "0.5"} />
                        <text x={pos.x} y={pos.y - 5} fill="#e0e0e0" fontSize="10" textAnchor="middle" fontWeight="600">{p.icon} {p.name.split(' ').slice(-1)}</text>
                        <text x={pos.x} y={pos.y + 10} fill="#666" fontSize="8" textAnchor="middle">{p.version} · {diagrams} diagrams</text>
                    </g>
                );
            })}
        </svg>
    );
}
