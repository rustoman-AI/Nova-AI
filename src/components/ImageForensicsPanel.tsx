import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface LayerCve { cve_id: string; severity: string; package: string; }
interface ImageLayer {
    index: number; hash: string; command: string; layer_type: string;
    size_mb: number; file_count: number; packages: string[]; cves: LayerCve[];
}
interface ImageAnalysis {
    image_name: string; image_tag: string; total_size_mb: number;
    total_layers: number; total_cves: number; layers: ImageLayer[];
}

const TYPE_COLORS: Record<string, string> = { base: "#58a6ff", packages: "#d2a8ff", application: "#3fb950", config: "#8b949e" };
const SEV_COLORS: Record<string, string> = { CRITICAL: "#ff7b72", HIGH: "#ffa657", MEDIUM: "#d2a8ff", LOW: "#58a6ff" };

const MOCK: ImageAnalysis = {
    image_name: "corp-registry.io/platform/api-gateway", image_tag: "v2.14.3-bookworm",
    total_size_mb: 177.0, total_layers: 8, total_cves: 6,
    layers: [
        { index: 0, hash: "sha256:a3ed95caeb02", command: "FROM debian:bookworm-slim", layer_type: "base", size_mb: 74.8, file_count: 8432, packages: ["libc6:2.36","libssl3:3.0.11","zlib1g:1.2.13","coreutils:9.1","bash:5.2"], cves: [{ cve_id: "CVE-2023-4911", severity: "HIGH", package: "libc6:2.36" }, { cve_id: "CVE-2023-5678", severity: "MEDIUM", package: "libssl3:3.0.11" }] },
        { index: 1, hash: "sha256:7b4d08708ebc", command: "RUN apt-get update && apt-get install -y curl wget ca-certificates gnupg", layer_type: "packages", size_mb: 42.3, file_count: 2891, packages: ["curl:7.88.1","wget:1.21.3","ca-certificates:20230311","gnupg:2.2.40"], cves: [{ cve_id: "CVE-2023-38545", severity: "CRITICAL", package: "curl:7.88.1" }, { cve_id: "CVE-2023-38546", severity: "LOW", package: "curl:7.88.1" }] },
        { index: 2, hash: "sha256:c2adabaecedb", command: "RUN apt-get install -y nginx=1.24.0-2 && rm -rf /var/lib/apt/lists/*", layer_type: "packages", size_mb: 18.6, file_count: 1247, packages: ["nginx:1.24.0","libpcre2-8-0:10.42","libgd3:2.3.3"], cves: [{ cve_id: "CVE-2023-44487", severity: "HIGH", package: "nginx:1.24.0" }] },
        { index: 3, hash: "sha256:e1b7d245f3c8", command: "RUN pip install flask==3.0.0 gunicorn==21.2.0 requests==2.31.0", layer_type: "packages", size_mb: 28.1, file_count: 3156, packages: ["flask:3.0.0","gunicorn:21.2.0","requests:2.31.0","jinja2:3.1.2","werkzeug:3.0.1"], cves: [{ cve_id: "CVE-2024-34064", severity: "MEDIUM", package: "jinja2:3.1.2" }] },
        { index: 4, hash: "sha256:9f82d4c7a1e5", command: "COPY ./app /opt/app", layer_type: "application", size_mb: 12.4, file_count: 847, packages: [], cves: [] },
        { index: 5, hash: "sha256:d3f2a8b91c4e", command: "COPY nginx.conf /etc/nginx/nginx.conf", layer_type: "config", size_mb: 0.02, file_count: 1, packages: [], cves: [] },
        { index: 6, hash: "sha256:b7e9c3d60f12", command: "RUN useradd -r appuser && chown -R appuser /opt/app", layer_type: "config", size_mb: 0.8, file_count: 24, packages: [], cves: [] },
        { index: 7, hash: "sha256:f4a1b8c25d93", command: "CMD [\"gunicorn\", \"--bind\", \"0.0.0.0:8000\", \"app:create_app()\"]", layer_type: "config", size_mb: 0, file_count: 0, packages: [], cves: [] },
    ]
};

export default function ImageForensicsPanel() {
    const [data, setData] = useState<ImageAnalysis | null>(null);
    const [expanded, setExpanded] = useState<Set<number>>(new Set([0]));

    const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

    useEffect(() => {
        (async () => {
            try {
                if (isTauri) {
                    setData(await invoke<ImageAnalysis>("engine_get_image_layers"));
                } else {
                    setData(MOCK);
                }
            } catch { setData(MOCK); }
        })();
    }, [isTauri]);

    if (!data) return <div style={{ padding: 40, color: "#8b949e" }}>Analyzing container image layers...</div>;

    const toggle = (idx: number) => {
        setExpanded(prev => { const n = new Set(prev); n.has(idx) ? n.delete(idx) : n.add(idx); return n; });
    };

    return (
        <div style={{ padding: "25px", height: "100%", overflow: "auto", color: "#c9d1d9" }}>
            {/* Header */}
            <div style={{ marginBottom: "20px" }}>
                <h2 style={{ margin: "0 0 5px", fontSize: "24px", color: "#58a6ff" }}>🔬 Container Image Layer Forensics</h2>
                <div style={{ display: "flex", alignItems: "center", gap: "12px", color: "#8b949e", fontSize: "13px" }}>
                    <span style={{ fontFamily: "monospace", color: "#d2a8ff", fontWeight: "bold" }}>{data.image_name}:{data.image_tag}</span>
                </div>
            </div>

            {/* Summary Cards */}
            <div style={{ display: "flex", gap: "12px", marginBottom: "20px" }}>
                {[
                    { label: "Total Size", value: `${data.total_size_mb} MB`, color: "#58a6ff" },
                    { label: "Layers", value: data.total_layers, color: "#d2a8ff" },
                    { label: "CVEs Found", value: data.total_cves, color: "#ff7b72" },
                    { label: "Base Image", value: "debian:bookworm", color: "#3fb950" },
                ].map(c => (
                    <div key={c.label} style={{ flex: 1, background: "#0d1117", border: `1px solid ${c.color}22`, borderRadius: "8px", padding: "14px", textAlign: "center" }}>
                        <div style={{ fontSize: "20px", fontWeight: "bold", color: c.color }}>{c.value}</div>
                        <div style={{ fontSize: "10px", color: "#8b949e", textTransform: "uppercase" }}>{c.label}</div>
                    </div>
                ))}
            </div>

            {/* Stacked Layer Bar */}
            <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", padding: "16px", marginBottom: "20px" }}>
                <div style={{ fontSize: "11px", color: "#8b949e", textTransform: "uppercase", fontWeight: "bold", marginBottom: "10px" }}>Layer Size Distribution</div>
                <div style={{ display: "flex", borderRadius: "6px", overflow: "hidden", height: "32px" }}>
                    {data.layers.filter(l => l.size_mb > 0).map(layer => {
                        const pct = (layer.size_mb / data.total_size_mb) * 100;
                        return (
                            <div key={layer.index} title={`Layer ${layer.index}: ${layer.size_mb} MB (${layer.layer_type})`} onClick={() => toggle(layer.index)} style={{
                                width: `${Math.max(pct, 1)}%`, background: TYPE_COLORS[layer.layer_type],
                                opacity: 0.8, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center",
                                fontSize: "10px", fontWeight: "bold", color: "#0d1117", transition: "opacity 0.2s",
                                borderRight: "1px solid #0d1117",
                            }}
                            onMouseEnter={e => (e.currentTarget.style.opacity = "1")}
                            onMouseLeave={e => (e.currentTarget.style.opacity = "0.8")}
                            >
                                {pct > 8 ? `L${layer.index}` : ""}
                            </div>
                        );
                    })}
                </div>
                <div style={{ display: "flex", gap: "16px", marginTop: "8px", fontSize: "10px" }}>
                    {Object.entries(TYPE_COLORS).map(([type, color]) => (
                        <div key={type} style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                            <div style={{ width: "10px", height: "10px", borderRadius: "2px", background: color }} />
                            <span style={{ color: "#8b949e", textTransform: "capitalize" }}>{type}</span>
                        </div>
                    ))}
                </div>
            </div>

            {/* Layer Cards */}
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {data.layers.map(layer => {
                    const isOpen = expanded.has(layer.index);
                    const typeColor = TYPE_COLORS[layer.layer_type];
                    return (
                        <div key={layer.index} style={{ background: "#0d1117", border: `1px solid ${isOpen ? typeColor + "66" : "#30363d"}`, borderRadius: "8px", overflow: "hidden", transition: "all 0.2s", borderLeft: `4px solid ${typeColor}` }}>
                            {/* Header */}
                            <div onClick={() => toggle(layer.index)} style={{ padding: "12px 16px", cursor: "pointer", display: "flex", alignItems: "center", gap: "12px" }}>
                                <span style={{ fontSize: "12px", color: "#6e7681", transition: "transform 0.2s", transform: isOpen ? "rotate(90deg)" : "rotate(0)" }}>▶</span>
                                <span style={{ fontSize: "11px", fontWeight: "bold", color: typeColor, textTransform: "uppercase", width: "70px" }}>{layer.layer_type}</span>
                                <span style={{ fontFamily: "monospace", fontSize: "12px", color: "#e6edf3", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{layer.command}</span>
                                <span style={{ fontSize: "11px", color: "#8b949e", fontFamily: "monospace" }}>{layer.size_mb > 0 ? `${layer.size_mb} MB` : "0 B"}</span>
                                <span style={{ fontSize: "11px", color: "#6e7681" }}>{layer.file_count} files</span>
                                {layer.cves.length > 0 && (
                                    <span style={{ fontSize: "10px", fontWeight: "bold", color: "#ff7b72", background: "#ff7b7222", padding: "2px 8px", borderRadius: "4px" }}>
                                        {layer.cves.length} CVE{layer.cves.length > 1 ? "s" : ""}
                                    </span>
                                )}
                            </div>
                            {/* Expanded Detail */}
                            {isOpen && (
                                <div style={{ padding: "0 16px 16px 44px", borderTop: "1px solid #21262d" }}>
                                    <div style={{ display: "flex", gap: "24px", marginTop: "12px", fontSize: "12px" }}>
                                        <div><span style={{ color: "#8b949e" }}>Hash: </span><span style={{ fontFamily: "monospace", color: "#6e7681" }}>{layer.hash}</span></div>
                                    </div>
                                    {layer.packages.length > 0 && (
                                        <div style={{ marginTop: "12px" }}>
                                            <div style={{ fontSize: "10px", color: "#8b949e", textTransform: "uppercase", fontWeight: "bold", marginBottom: "6px" }}>Packages ({layer.packages.length})</div>
                                            <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                                                {layer.packages.map(pkg => {
                                                    const hasCve = layer.cves.some(c => c.package === pkg);
                                                    return (
                                                        <span key={pkg} style={{ fontSize: "11px", fontFamily: "monospace", padding: "3px 8px", borderRadius: "4px", background: hasCve ? "#ff7b7215" : "#161b22", color: hasCve ? "#ff7b72" : "#c9d1d9", border: hasCve ? "1px solid #ff7b7233" : "1px solid #21262d" }}>
                                                            {pkg} {hasCve && "⚠"}
                                                        </span>
                                                    );
                                                })}
                                            </div>
                                        </div>
                                    )}
                                    {layer.cves.length > 0 && (
                                        <div style={{ marginTop: "12px" }}>
                                            <div style={{ fontSize: "10px", color: "#ff7b72", textTransform: "uppercase", fontWeight: "bold", marginBottom: "6px" }}>Attributed CVEs</div>
                                            {layer.cves.map(cve => (
                                                <div key={cve.cve_id} style={{ display: "flex", alignItems: "center", gap: "10px", padding: "6px 0", fontSize: "12px" }}>
                                                    <span style={{ fontSize: "10px", fontWeight: "bold", color: SEV_COLORS[cve.severity], border: `1px solid ${SEV_COLORS[cve.severity]}44`, padding: "1px 6px", borderRadius: "3px" }}>{cve.severity}</span>
                                                    <span style={{ fontFamily: "monospace", color: SEV_COLORS[cve.severity], fontWeight: "bold" }}>{cve.cve_id}</span>
                                                    <span style={{ color: "#8b949e" }}>in</span>
                                                    <span style={{ fontFamily: "monospace", color: "#d2a8ff" }}>{cve.package}</span>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                    {layer.packages.length === 0 && layer.cves.length === 0 && (
                                        <div style={{ marginTop: "12px", fontSize: "12px", color: "#3fb950" }}>✓ Clean layer — no packages or vulnerabilities</div>
                                    )}
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
