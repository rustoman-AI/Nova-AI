import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ─── Types ─────────────────────────────────────────
interface Claim {
    "bom-ref"?: string;
    target?: string;
    predicate?: string;
    mitigationStrategies?: string[];
    reasoning?: string;
    evidence?: string[];
    counterEvidence?: string[];
    externalReferences?: { url?: string; type?: string }[];
}

interface Evidence {
    "bom-ref"?: string;
    propertyName?: string;
    description?: string;
    data?: { contents?: { attachment?: { contentType?: string; content?: string } } };
    created?: string;
    expires?: string;
    author?: { name?: string; email?: string };
}

interface Conformance {
    score?: number;
    rationale?: string;
    mitigationStrategies?: string[];
}

interface Assessor {
    "bom-ref"?: string;
    thirdParty?: boolean;
    organization?: { name?: string; url?: string[] };
}

interface Affirmation {
    statement?: string;
    signatories?: { name?: string; role?: string; organization?: { name?: string }; externalReference?: { url?: string } }[];
}

interface Attestation {
    summary?: string;
    assessor?: string;
    map?: { requirement?: string; claims?: string[]; counterClaims?: string[]; conformance?: Conformance }[];
}

interface Declarations {
    assessors?: Assessor[];
    attestations?: Attestation[];
    claims?: Claim[];
    evidence?: Evidence[];
    targets?: { organizations?: any[]; components?: any[]; services?: any[] };
    affirmation?: Affirmation;
}

// ─── Main Component ────────────────────────────────
export default function AttestationDashboard() {
    const [decl, setDecl] = useState<Declarations | null>(null);
    const [loaded, setLoaded] = useState(false);

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select CycloneDX 1.6 BOM",
        });
        if (!f) return;
        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom = JSON.parse(content);
        setDecl(bom.declarations || null);
        setLoaded(true);
    }, []);

    const claims = decl?.claims || [];
    const evidence = decl?.evidence || [];
    const assessors = decl?.assessors || [];
    const attestations = decl?.attestations || [];
    const affirmation = decl?.affirmation;

    // Evidence lookup
    const evidenceMap = useMemo(() => {
        const m = new Map<string, Evidence>();
        for (const e of evidence) if (e["bom-ref"]) m.set(e["bom-ref"], e);
        return m;
    }, [evidence]);

    const hasData = claims.length > 0 || attestations.length > 0 || affirmation;

    return (
        <div className="attest-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">Attestation & Declarations</h2>
                <button className="exec-btn" onClick={loadBom}>📁 Open BOM</button>
                {hasData && (
                    <div className="depgraph-stats">
                        <span className="depgraph-stat">{claims.length} claims</span>
                        <span className="depgraph-stat">{evidence.length} evidence</span>
                        <span className="depgraph-stat">{assessors.length} assessors</span>
                        <span className="depgraph-stat">{attestations.length} attestations</span>
                    </div>
                )}
            </div>

            {hasData ? (
                <div className="attest-content fade-in">
                    {/* Assessors */}
                    {assessors.length > 0 && (
                        <div className="attest-section">
                            <h4>👤 Assessors ({assessors.length})</h4>
                            <div className="attest-assessors">
                                {assessors.map((a, i) => (
                                    <div key={i} className="attest-assessor-card">
                                        <div className="attest-assessor-name">
                                            {a.organization?.name || a["bom-ref"] || "Unknown"}
                                        </div>
                                        {a.thirdParty !== undefined && (
                                            <span className={`attest-badge ${a.thirdParty ? "attest-badge-third" : "attest-badge-internal"}`}>
                                                {a.thirdParty ? "Third-party" : "Internal"}
                                            </span>
                                        )}
                                        {a.organization?.url?.map((u, j) => (
                                            <div key={j} className="attest-assessor-url">{u}</div>
                                        ))}
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Claims Table */}
                    {claims.length > 0 && (
                        <div className="attest-section">
                            <h4>📋 Claims ({claims.length})</h4>
                            <div className="lic-table-wrap">
                                <table className="lic-table">
                                    <thead>
                                        <tr>
                                            <th>Ref</th>
                                            <th>Target</th>
                                            <th>Predicate</th>
                                            <th>Evidence</th>
                                            <th>Counter</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {claims.map((c, i) => (
                                            <tr key={i}>
                                                <td className="lic-id">{c["bom-ref"] || `#${i + 1}`}</td>
                                                <td>{c.target || "—"}</td>
                                                <td className="attest-predicate">{c.predicate || "—"}</td>
                                                <td>
                                                    {(c.evidence || []).map((eRef, j) => {
                                                        const ev = evidenceMap.get(eRef);
                                                        return <span key={j} className="attest-ev-badge" title={ev?.description || eRef}>
                                                            📄 {ev?.propertyName || eRef}
                                                        </span>;
                                                    })}
                                                    {(!c.evidence || c.evidence.length === 0) && "—"}
                                                </td>
                                                <td>
                                                    {(c.counterEvidence || []).length > 0 ? (
                                                        <span className="attest-counter-badge">⚠️ {c.counterEvidence!.length}</span>
                                                    ) : "—"}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* Compliance Matrix (attestation maps) */}
                    {attestations.length > 0 && attestations.some(a => a.map && a.map.length > 0) && (
                        <div className="attest-section">
                            <h4>⚖️ Compliance Matrix</h4>
                            {attestations.map((att, ai) => (
                                <div key={ai} className="attest-matrix-block">
                                    {att.summary && <div className="attest-matrix-summary">{att.summary}</div>}
                                    <div className="lic-table-wrap">
                                        <table className="lic-table">
                                            <thead>
                                                <tr>
                                                    <th>Requirement</th>
                                                    <th>Claims</th>
                                                    <th>Score</th>
                                                    <th>Status</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {(att.map || []).map((m, mi) => {
                                                    const score = m.conformance?.score;
                                                    const status = score === undefined ? "unknown" :
                                                        score >= 0.8 ? "pass" : score >= 0.5 ? "partial" : "fail";
                                                    return (
                                                        <tr key={mi}>
                                                            <td className="lic-id">{m.requirement || `#${mi + 1}`}</td>
                                                            <td>{(m.claims || []).length} claims</td>
                                                            <td>
                                                                {score !== undefined ? (
                                                                    <span className={`attest-score attest-score-${status}`}>
                                                                        {Math.round(score * 100)}%
                                                                    </span>
                                                                ) : "—"}
                                                            </td>
                                                            <td>
                                                                <span className={`attest-status attest-status-${status}`}>
                                                                    {status === "pass" ? "✅ Conformant" :
                                                                        status === "partial" ? "⚠️ Partial" :
                                                                            status === "fail" ? "❌ Non-conformant" : "❓ Unknown"}
                                                                </span>
                                                            </td>
                                                        </tr>
                                                    );
                                                })}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}

                    {/* Evidence */}
                    {evidence.length > 0 && (
                        <div className="attest-section">
                            <h4>📄 Evidence ({evidence.length})</h4>
                            <div className="attest-evidence-list">
                                {evidence.map((e, i) => (
                                    <div key={i} className="attest-ev-card">
                                        <div className="attest-ev-header">
                                            <span className="lic-id">{e["bom-ref"] || `#${i + 1}`}</span>
                                            {e.propertyName && <span className="attest-ev-prop">{e.propertyName}</span>}
                                        </div>
                                        {e.description && <div className="attest-ev-desc">{e.description}</div>}
                                        <div className="attest-ev-meta">
                                            {e.created && <span>Created: {e.created}</span>}
                                            {e.expires && <span>Expires: {e.expires}</span>}
                                            {e.author?.name && <span>Author: {e.author.name}</span>}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Affirmation */}
                    {affirmation && (
                        <div className="attest-section">
                            <h4>✍️ Affirmation</h4>
                            <div className="attest-affirm-card">
                                {affirmation.statement && (
                                    <div className="attest-affirm-statement">{affirmation.statement}</div>
                                )}
                                {affirmation.signatories && affirmation.signatories.length > 0 && (
                                    <div className="attest-signatories">
                                        <b>Signatories:</b>
                                        {affirmation.signatories.map((s, i) => (
                                            <div key={i} className="attest-signatory">
                                                {s.name || "Unknown"} {s.role && `(${s.role})`}
                                                {s.organization?.name && ` — ${s.organization.name}`}
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>
                    )}
                </div>
            ) : (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">📜</span>
                    <h3>Attestation & Declarations</h3>
                    <p>Open a CycloneDX 1.6+ BOM with <code>declarations</code> to view claims, evidence, conformance, and compliance attestations</p>
                    {loaded && <p className="cbom-no-crypto">ℹ️ This BOM does not contain declarations data</p>}
                </div>
            )}
        </div>
    );
}
