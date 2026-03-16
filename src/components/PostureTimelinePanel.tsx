import { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

interface PostureSnapshot {
    date: string;
    total_cves: number;
    critical_cves: number;
    compliance_score: number;
    sbom_completeness: number;
    mttr_hours: number;
    active_threats: number;
}

const MOCK_DATA: PostureSnapshot[] = Array.from({ length: 30 }, (_, i) => {
    const d = new Date(2024, 10, 10 + i);
    const base = {
        total_cves: Math.round(45 - i * 0.8 + (Math.random() - 0.5) * 6),
        critical_cves: Math.round(12 - i * 0.3 + (Math.random() - 0.5) * 3),
        compliance_score: Math.round((62 + i * 1.1 + (Math.random() - 0.3) * 4) * 10) / 10,
        sbom_completeness: Math.round((71 + i * 0.8 + (Math.random() - 0.3) * 3) * 10) / 10,
        mttr_hours: Math.round((96 - i * 2.2 + (Math.random() - 0.5) * 8) * 10) / 10,
        active_threats: Math.round(18 - i * 0.4 + (Math.random() - 0.5) * 5),
    };
    return {
        date: d.toISOString().split("T")[0],
        total_cves: Math.max(8, Math.min(55, base.total_cves)),
        critical_cves: Math.max(1, Math.min(20, base.critical_cves)),
        compliance_score: Math.max(50, Math.min(98, base.compliance_score)),
        sbom_completeness: Math.max(60, Math.min(99, base.sbom_completeness)),
        mttr_hours: Math.max(12, Math.min(120, base.mttr_hours)),
        active_threats: Math.max(2, Math.min(25, base.active_threats)),
    };
});

interface SparklineProps {
    data: number[];
    color: string;
    height: number;
    invertTrend?: boolean;
    label: string;
    unit: string;
    selectedIdx: number | null;
    onHover: (idx: number | null) => void;
}

function Sparkline({ data, color, height, invertTrend, label, unit, selectedIdx, onHover }: SparklineProps) {
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const containerRef = useRef<HTMLDivElement>(null);

    const first = data[0];
    const last = data[data.length - 1];
    const delta = last - first;
    const improving = invertTrend ? delta < 0 : delta > 0;
    const pctChange = first !== 0 ? Math.abs((delta / first) * 100).toFixed(1) : "0";

    const draw = useCallback(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        const w = canvas.width;
        const h = canvas.height;
        ctx.clearRect(0, 0, w, h);

        const min = Math.min(...data) * 0.9;
        const max = Math.max(...data) * 1.1;
        const range = max - min || 1;

        // Fill gradient
        const grad = ctx.createLinearGradient(0, 0, 0, h);
        grad.addColorStop(0, color + "33");
        grad.addColorStop(1, color + "05");

        ctx.beginPath();
        ctx.moveTo(0, h);
        data.forEach((val, i) => {
            const x = (i / (data.length - 1)) * w;
            const y = h - ((val - min) / range) * (h - 10);
            if (i === 0) ctx.lineTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.lineTo(w, h);
        ctx.closePath();
        ctx.fillStyle = grad;
        ctx.fill();

        // Line
        ctx.beginPath();
        data.forEach((val, i) => {
            const x = (i / (data.length - 1)) * w;
            const y = h - ((val - min) / range) * (h - 10);
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.stroke();

        // Selected point
        if (selectedIdx !== null && selectedIdx >= 0 && selectedIdx < data.length) {
            const x = (selectedIdx / (data.length - 1)) * w;
            const y = h - ((data[selectedIdx] - min) / range) * (h - 10);
            ctx.beginPath();
            ctx.arc(x, y, 5, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.fill();
            ctx.beginPath();
            ctx.arc(x, y, 8, 0, Math.PI * 2);
            ctx.strokeStyle = color + "66";
            ctx.lineWidth = 2;
            ctx.stroke();
        }
    }, [data, color, selectedIdx]);

    useEffect(() => { draw(); }, [draw]);

    const handleMouseMove = (e: React.MouseEvent) => {
        const rect = containerRef.current?.getBoundingClientRect();
        if (!rect) return;
        const x = e.clientX - rect.left;
        const idx = Math.round((x / rect.width) * (data.length - 1));
        onHover(Math.max(0, Math.min(data.length - 1, idx)));
    };

    return (
        <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", padding: "15px", flex: 1 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                <div style={{ fontSize: "12px", color: "#8b949e", textTransform: "uppercase", fontWeight: "bold" }}>{label}</div>
                <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <span style={{ fontSize: "18px", fontWeight: "bold", color }}>{selectedIdx !== null ? data[selectedIdx] : last}</span>
                    <span style={{ fontSize: "11px", color }}>{unit}</span>
                    <span style={{ fontSize: "11px", color: improving ? "#3fb950" : "#f85149", fontWeight: "bold" }}>
                        {improving ? "↑" : "↓"} {pctChange}%
                    </span>
                </div>
            </div>
            <div
                ref={containerRef}
                onMouseMove={handleMouseMove}
                onMouseLeave={() => onHover(null)}
                style={{ cursor: "crosshair" }}
            >
                <canvas ref={canvasRef} width={400} height={height} style={{ width: "100%", height: `${height}px` }} />
            </div>
        </div>
    );
}

export default function PostureTimelinePanel() {
    const [snapshots, setSnapshots] = useState<PostureSnapshot[]>([]);
    const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);
    const [loading, setLoading] = useState(true);

    const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

    useEffect(() => {
        (async () => {
            try {
                if (isTauri) {
                    const data = await invoke<PostureSnapshot[]>("engine_get_posture_timeline");
                    setSnapshots(data);
                } else {
                    setSnapshots(MOCK_DATA);
                }
            } catch {
                setSnapshots(MOCK_DATA);
            }
            setLoading(false);
        })();
    }, [isTauri]);

    if (loading) return <div style={{ padding: 40, color: "#8b949e" }}>Loading security posture timeline...</div>;

    const latest = snapshots[snapshots.length - 1];
    const first = snapshots[0];
    const hovered = hoveredIdx !== null ? snapshots[hoveredIdx] : null;

    return (
        <div style={{ padding: "25px", height: "100%", display: "flex", flexDirection: "column", color: "#c9d1d9", overflow: "auto" }}>
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
                <div>
                    <h2 style={{ margin: "0 0 5px", fontSize: "24px", color: "#58a6ff" }}>📈 Security Posture Timeline</h2>
                    <p style={{ color: "#8b949e", margin: 0 }}>30-day trend analysis — CVEs, compliance, SBOM completeness, and remediation velocity.</p>
                </div>
                {hovered && (
                    <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "8px", padding: "10px 15px", fontSize: "12px" }}>
                        <div style={{ fontWeight: "bold", color: "#58a6ff", marginBottom: "4px" }}>📅 {hovered.date}</div>
                        <div style={{ color: "#8b949e" }}>CVEs: <span style={{ color: "#ff7b72" }}>{hovered.total_cves}</span> | Critical: <span style={{ color: "#f85149" }}>{hovered.critical_cves}</span> | Compliance: <span style={{ color: "#3fb950" }}>{hovered.compliance_score}%</span></div>
                    </div>
                )}
            </div>

            {/* Current Posture Summary */}
            <div style={{ display: "flex", gap: "10px", marginBottom: "20px" }}>
                {[
                    { label: "Total CVEs", value: latest.total_cves, prev: first.total_cves, color: "#ff7b72", invert: true },
                    { label: "Critical", value: latest.critical_cves, prev: first.critical_cves, color: "#f85149", invert: true },
                    { label: "Compliance", value: `${latest.compliance_score}%`, prev: first.compliance_score, curr: latest.compliance_score, color: "#3fb950", invert: false },
                    { label: "SBOM Complete", value: `${latest.sbom_completeness}%`, prev: first.sbom_completeness, curr: latest.sbom_completeness, color: "#58a6ff", invert: false },
                    { label: "MTTR", value: `${latest.mttr_hours}h`, prev: first.mttr_hours, curr: latest.mttr_hours, color: "#d2a8ff", invert: true },
                    { label: "Threats", value: latest.active_threats, prev: first.active_threats, color: "#ffa657", invert: true },
                ].map(card => {
                    const currNum = typeof card.value === "string" ? (card as any).curr ?? 0 : card.value as number;
                    const delta = currNum - card.prev;
                    const improving = card.invert ? delta < 0 : delta > 0;
                    return (
                        <div key={card.label} style={{ flex: 1, background: "#0d1117", border: `1px solid ${card.color}22`, borderRadius: "8px", padding: "12px", textAlign: "center" }}>
                            <div style={{ fontSize: "20px", fontWeight: "bold", color: card.color }}>{card.value}</div>
                            <div style={{ fontSize: "10px", color: "#8b949e", textTransform: "uppercase", marginBottom: "4px" }}>{card.label}</div>
                            <div style={{ fontSize: "10px", fontWeight: "bold", color: improving ? "#3fb950" : "#f85149" }}>
                                {improving ? "↑" : "↓"} {delta > 0 ? "+" : ""}{typeof delta === "number" ? (Number.isInteger(delta) ? delta : delta.toFixed(1)) : delta}
                            </div>
                        </div>
                    );
                })}
            </div>

            {/* Sparkline Charts - Row 1 */}
            <div style={{ display: "flex", gap: "12px", marginBottom: "12px" }}>
                <Sparkline data={snapshots.map(s => s.total_cves)} color="#ff7b72" height={100} invertTrend label="Total CVEs" unit="vulns" selectedIdx={hoveredIdx} onHover={setHoveredIdx} />
                <Sparkline data={snapshots.map(s => s.compliance_score)} color="#3fb950" height={100} label="Compliance Score" unit="%" selectedIdx={hoveredIdx} onHover={setHoveredIdx} />
                <Sparkline data={snapshots.map(s => s.sbom_completeness)} color="#58a6ff" height={100} label="SBOM Completeness" unit="%" selectedIdx={hoveredIdx} onHover={setHoveredIdx} />
            </div>

            {/* Sparkline Charts - Row 2 */}
            <div style={{ display: "flex", gap: "12px", marginBottom: "20px" }}>
                <Sparkline data={snapshots.map(s => s.critical_cves)} color="#f85149" height={100} invertTrend label="Critical CVEs" unit="vulns" selectedIdx={hoveredIdx} onHover={setHoveredIdx} />
                <Sparkline data={snapshots.map(s => s.mttr_hours)} color="#d2a8ff" height={100} invertTrend label="Mean Time to Remediate" unit="hours" selectedIdx={hoveredIdx} onHover={setHoveredIdx} />
                <Sparkline data={snapshots.map(s => s.active_threats)} color="#ffa657" height={100} invertTrend label="Active Threats" unit="threats" selectedIdx={hoveredIdx} onHover={setHoveredIdx} />
            </div>

            {/* Snapshot Table */}
            <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", overflow: "hidden" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
                    <thead>
                        <tr style={{ background: "#161b22" }}>
                            {["Date", "CVEs", "Critical", "Compliance", "SBOM %", "MTTR (h)", "Threats"].map(h => (
                                <th key={h} style={{ padding: "10px 12px", textAlign: "left", color: "#8b949e", fontWeight: "bold", borderBottom: "1px solid #30363d", fontSize: "11px", textTransform: "uppercase" }}>{h}</th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {[...snapshots].reverse().slice(0, 10).map((s, idx) => (
                            <tr key={s.date} style={{ borderBottom: "1px solid #21262d", background: idx === 0 ? "#161b2244" : undefined }}>
                                <td style={{ padding: "8px 12px", fontFamily: "monospace", color: "#58a6ff" }}>{s.date}</td>
                                <td style={{ padding: "8px 12px", color: "#ff7b72", fontWeight: "bold" }}>{s.total_cves}</td>
                                <td style={{ padding: "8px 12px", color: "#f85149", fontWeight: "bold" }}>{s.critical_cves}</td>
                                <td style={{ padding: "8px 12px", color: "#3fb950" }}>{s.compliance_score}%</td>
                                <td style={{ padding: "8px 12px", color: "#58a6ff" }}>{s.sbom_completeness}%</td>
                                <td style={{ padding: "8px 12px", color: "#d2a8ff" }}>{s.mttr_hours}</td>
                                <td style={{ padding: "8px 12px", color: "#ffa657" }}>{s.active_threats}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
