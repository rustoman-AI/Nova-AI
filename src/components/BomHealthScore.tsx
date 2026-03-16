import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ─── Dimension definitions ────────────────────────
const DIMENSIONS = [
    { key: "completeness", label: "Completeness", icon: "📦" },
    { key: "freshness", label: "Freshness", icon: "🕐" },
    { key: "security", label: "Security", icon: "🛡️" },
    { key: "license", label: "Licenses", icon: "🏷️" },
    { key: "deps", label: "Dependencies", icon: "🕸️" },
    { key: "crypto", label: "Crypto", icon: "🔐" },
    { key: "provenance", label: "Provenance", icon: "🏗️" },
    { key: "attestation", label: "Attestation", icon: "📜" },
    { key: "metadata", label: "Metadata", icon: "📋" },
    { key: "ntia", label: "NTIA Min.", icon: "🇺🇸" },
] as const;

type DimKey = typeof DIMENSIONS[number]["key"];

interface DimScore { score: number; details: string; suggestions: string[]; }

function gradeFromScore(s: number): { grade: string; color: string } {
    if (s >= 90) return { grade: "A", color: "#22c55e" };
    if (s >= 75) return { grade: "B", color: "#84cc16" };
    if (s >= 60) return { grade: "C", color: "#f59e0b" };
    if (s >= 40) return { grade: "D", color: "#f97316" };
    return { grade: "F", color: "#ef4444" };
}

// ─── Analysis Engine ───────────────────────────────
function analyzeBom(bom: any): Record<DimKey, DimScore> {
    const components: any[] = bom.components || [];
    const total = components.length || 1;

    // Completeness: purl, hashes, licenses, supplier
    const hasPurl = components.filter(c => c.purl).length;
    const hasHash = components.filter(c => c.hashes?.length).length;
    const hasLic = components.filter(c => c.licenses?.length).length;
    const hasSupp = components.filter(c => c.supplier?.name || c.publisher).length;
    const compScore = Math.round(((hasPurl + hasHash + hasLic + hasSupp) / (total * 4)) * 100);
    const compSugg: string[] = [];
    if (hasPurl < total) compSugg.push(`Add PURLs to ${total - hasPurl} components`);
    if (hasHash < total) compSugg.push(`Add hashes to ${total - hasHash} components`);
    if (hasLic < total) compSugg.push(`Add licenses to ${total - hasLic} components`);

    // Freshness: check if metadata.timestamp exists, modified dates
    const hasTimestamp = bom.metadata?.timestamp ? 1 : 0;
    const hasToolVersion = bom.metadata?.tools?.length ? 1 : 0;
    const freshScore = Math.round(((hasTimestamp + hasToolVersion) / 2) * 100);
    const freshSugg: string[] = [];
    if (!hasTimestamp) freshSugg.push("Add metadata.timestamp to BOM");

    // Security: vulnerabilities present  
    const vulns: any[] = bom.vulnerabilities || [];
    const hasVex = vulns.length > 0 ? 100 : 0;
    const secSugg: string[] = [];
    if (!vulns.length) secSugg.push("Add vulnerability/VEX data");

    // License
    const unknownLic = components.filter(c => !c.licenses?.length).length;
    const licScore = Math.round(((total - unknownLic) / total) * 100);
    const licSugg: string[] = [];
    if (unknownLic > 0) licSugg.push(`Identify licenses for ${unknownLic} components`);

    // Dependencies
    const deps: any[] = bom.dependencies || [];
    const depsScore = deps.length > 0 ? 100 : 0;
    const depsSugg: string[] = [];
    if (!deps.length) depsSugg.push("Add dependency tree");

    // Crypto
    const hasCrypto = components.some(c => c.cryptoProperties);
    const cryptoScore = hasCrypto ? 100 : 0;
    const cryptoSugg: string[] = [];
    if (!hasCrypto) cryptoSugg.push("Add cryptoProperties for CBOM compliance");

    // Provenance
    const hasForm = (bom.formulation || []).length > 0;
    const provScore = hasForm ? 100 : 0;
    const provSugg: string[] = [];
    if (!hasForm) provSugg.push("Add formulation[] for build provenance");

    // Attestation
    const hasDecl = bom.declarations?.claims?.length > 0;
    const attScore = hasDecl ? 100 : 0;
    const attSugg: string[] = [];
    if (!hasDecl) attSugg.push("Add declarations for attestation compliance");

    // Metadata
    let metaScore = 0;
    const metaParts: string[] = [];
    if (bom.bomFormat) { metaScore += 20; } else { metaParts.push("bomFormat"); }
    if (bom.specVersion) { metaScore += 20; } else { metaParts.push("specVersion"); }
    if (bom.serialNumber) { metaScore += 20; } else { metaParts.push("serialNumber"); }
    if (bom.version !== undefined) { metaScore += 20; } else { metaParts.push("version"); }
    if (bom.metadata?.component) { metaScore += 20; } else { metaParts.push("metadata.component"); }
    const metaSugg = metaParts.length ? [`Add missing: ${metaParts.join(", ")}`] : [];

    // NTIA Minimum Elements
    let ntiaScore = 0;
    const ntiaMissing: string[] = [];
    if (bom.metadata?.component?.supplier?.name || bom.metadata?.component?.author) ntiaScore += 14; else ntiaMissing.push("Supplier name");
    if (bom.metadata?.component?.name) ntiaScore += 14; else ntiaMissing.push("Component name");
    if (bom.metadata?.component?.version) ntiaScore += 14; else ntiaMissing.push("Version");
    if (hasPurl > 0) ntiaScore += 14; else ntiaMissing.push("Unique identifiers");
    if (deps.length > 0) ntiaScore += 15; else ntiaMissing.push("Dependency relationships");
    if (bom.metadata?.authors?.length || bom.metadata?.component?.author) ntiaScore += 15; else ntiaMissing.push("Author");
    if (bom.metadata?.timestamp) ntiaScore += 14; else ntiaMissing.push("Timestamp");
    const ntiaSugg = ntiaMissing.length ? [`Missing: ${ntiaMissing.join(", ")}`] : [];

    return {
        completeness: { score: compScore, details: `${hasPurl}/${total} PURL, ${hasHash}/${total} hash, ${hasLic}/${total} lic, ${hasSupp}/${total} supplier`, suggestions: compSugg },
        freshness: { score: freshScore, details: `Timestamp: ${hasTimestamp ? "✅" : "❌"}, Tools: ${hasToolVersion ? "✅" : "❌"}`, suggestions: freshSugg },
        security: { score: hasVex, details: `${vulns.length} vulnerabilities`, suggestions: secSugg },
        license: { score: licScore, details: `${total - unknownLic}/${total} licensed`, suggestions: licSugg },
        deps: { score: depsScore, details: `${deps.length} dependency entries`, suggestions: depsSugg },
        crypto: { score: cryptoScore, details: hasCrypto ? "CBOM data present" : "No crypto data", suggestions: cryptoSugg },
        provenance: { score: provScore, details: hasForm ? "Build provenance present" : "No formulation", suggestions: provSugg },
        attestation: { score: attScore, details: hasDecl ? "Declarations present" : "No attestation", suggestions: attSugg },
        metadata: { score: metaScore, details: `${Math.round(metaScore / 20)}/5 fields`, suggestions: metaSugg },
        ntia: { score: ntiaScore, details: `${7 - ntiaMissing.length}/7 minimum elements`, suggestions: ntiaSugg },
    };
}

// ─── SVG Radar Chart ───────────────────────────────
function RadarChart({ scores }: { scores: Record<DimKey, DimScore> }) {
    const cx = 150, cy = 150, r = 110;
    const dims = DIMENSIONS;
    const n = dims.length;

    const points = dims.map((d, i) => {
        const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
        const val = scores[d.key].score / 100;
        return {
            x: cx + r * val * Math.cos(angle),
            y: cy + r * val * Math.sin(angle),
            lx: cx + (r + 18) * Math.cos(angle),
            ly: cy + (r + 18) * Math.sin(angle),
            label: d.label,
            score: scores[d.key].score,
        };
    });

    // Grid rings
    const rings = [0.25, 0.5, 0.75, 1.0];

    return (
        <svg viewBox="0 0 300 300" className="health-radar">
            {/* Grid */}
            {rings.map((ring, ri) => (
                <polygon key={ri}
                    points={dims.map((_, i) => {
                        const a = (Math.PI * 2 * i) / n - Math.PI / 2;
                        return `${cx + r * ring * Math.cos(a)},${cy + r * ring * Math.sin(a)}`;
                    }).join(" ")}
                    fill="none" stroke="var(--border-subtle)" strokeWidth="0.5" opacity={0.5}
                />
            ))}
            {/* Axes */}
            {dims.map((_, i) => {
                const a = (Math.PI * 2 * i) / n - Math.PI / 2;
                return <line key={i} x1={cx} y1={cy} x2={cx + r * Math.cos(a)} y2={cy + r * Math.sin(a)}
                    stroke="var(--border-subtle)" strokeWidth="0.5" opacity={0.3} />;
            })}
            {/* Data polygon */}
            <polygon
                points={points.map(p => `${p.x},${p.y}`).join(" ")}
                fill="rgba(99,102,241,0.15)" stroke="#6366f1" strokeWidth="2"
            />
            {/* Data dots */}
            {points.map((p, i) => (
                <circle key={i} cx={p.x} cy={p.y} r="3.5" fill={gradeFromScore(p.score).color} stroke="#fff" strokeWidth="1" />
            ))}
            {/* Labels */}
            {points.map((p, i) => (
                <text key={i} x={p.lx} y={p.ly} textAnchor="middle" dominantBaseline="central"
                    fontSize="7" fill="var(--text-muted)" fontWeight="500">
                    {p.label}
                </text>
            ))}
        </svg>
    );
}

// ─── Main Component ────────────────────────────────
export default function BomHealthScore() {
    const [scores, setScores] = useState<Record<DimKey, DimScore> | null>(null);
    const [loaded, setLoaded] = useState(false);

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select BOM file",
        });
        if (!f) return;
        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom = JSON.parse(content);
        setScores(analyzeBom(bom));
        setLoaded(true);
    }, []);

    const overall = useMemo(() => {
        if (!scores) return 0;
        const weights: Record<DimKey, number> = {
            completeness: 20, freshness: 5, security: 15, license: 15, deps: 10,
            crypto: 5, provenance: 5, attestation: 5, metadata: 10, ntia: 10,
        };
        let sum = 0, wSum = 0;
        for (const d of DIMENSIONS) {
            sum += scores[d.key].score * weights[d.key];
            wSum += weights[d.key];
        }
        return Math.round(sum / wSum);
    }, [scores]);

    const { grade, color } = gradeFromScore(overall);

    const allSuggestions = useMemo(() => {
        if (!scores) return [];
        const sugg: { dim: string; icon: string; text: string }[] = [];
        for (const d of DIMENSIONS) {
            for (const s of scores[d.key].suggestions) {
                sugg.push({ dim: d.label, icon: d.icon, text: s });
            }
        }
        return sugg;
    }, [scores]);

    return (
        <div className="health-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">BOM Health Score</h2>
                <button className="exec-btn" onClick={loadBom}>📁 Open BOM</button>
            </div>

            {scores ? (
                <div className="health-content fade-in">
                    <div className="health-top">
                        {/* Overall grade */}
                        <div className="health-grade-card">
                            <div className="health-grade" style={{ color, borderColor: color }}>{grade}</div>
                            <div className="health-grade-score">{overall}%</div>
                            <div className="health-grade-label">Overall Health</div>
                        </div>

                        {/* Radar chart */}
                        <div className="health-radar-wrap">
                            <RadarChart scores={scores} />
                        </div>
                    </div>

                    {/* Dimension cards */}
                    <div className="health-dims">
                        {DIMENSIONS.map(d => {
                            const s = scores[d.key];
                            const { color: c } = gradeFromScore(s.score);
                            return (
                                <div key={d.key} className="health-dim-card">
                                    <div className="health-dim-header">
                                        <span>{d.icon} {d.label}</span>
                                        <span className="health-dim-score" style={{ color: c }}>{s.score}%</span>
                                    </div>
                                    <div className="health-dim-bar">
                                        <div className="health-dim-fill" style={{ width: `${s.score}%`, background: c }} />
                                    </div>
                                    <div className="health-dim-detail">{s.details}</div>
                                </div>
                            );
                        })}
                    </div>

                    {/* Improvement suggestions */}
                    {allSuggestions.length > 0 && (
                        <div className="health-suggestions">
                            <h4>💡 Improvement Suggestions ({allSuggestions.length})</h4>
                            {allSuggestions.map((s, i) => (
                                <div key={i} className="health-sugg-item">
                                    <span>{s.icon}</span>
                                    <span className="health-sugg-dim">{s.dim}:</span>
                                    <span>{s.text}</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            ) : (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">📊</span>
                    <h3>BOM Health Score</h3>
                    <p>Open any CycloneDX BOM to get a composite quality assessment across 10 dimensions</p>
                    {loaded && <p className="cbom-no-crypto">ℹ️ Could not analyze this BOM</p>}
                </div>
            )}
        </div>
    );
}
