import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ─── License classification data ───────────────────
const COPYLEFT: Record<string, "strong" | "weak" | "network"> = {
    "GPL-2.0-only": "strong", "GPL-2.0-or-later": "strong",
    "GPL-3.0-only": "strong", "GPL-3.0-or-later": "strong",
    "LGPL-2.0-only": "weak", "LGPL-2.0-or-later": "weak",
    "LGPL-2.1-only": "weak", "LGPL-2.1-or-later": "weak",
    "LGPL-3.0-only": "weak", "LGPL-3.0-or-later": "weak",
    "AGPL-3.0-only": "network", "AGPL-3.0-or-later": "network",
    "MPL-2.0": "weak", "EPL-1.0": "weak", "EPL-2.0": "weak",
    "EUPL-1.1": "strong", "EUPL-1.2": "strong",
    "CPAL-1.0": "network", "OSL-3.0": "network",
};

const PERMISSIVE = new Set([
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense",
    "0BSD", "CC0-1.0", "Zlib", "BSL-1.0", "PSF-2.0", "WTFPL",
    "X11", "Artistic-2.0", "PostgreSQL", "NCSA",
]);

const OSI_APPROVED = new Set([
    "MIT", "Apache-2.0", "GPL-2.0-only", "GPL-3.0-only", "LGPL-2.1-only",
    "LGPL-3.0-only", "AGPL-3.0-only", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "MPL-2.0", "EPL-2.0", "CPAL-1.0", "OSL-3.0", "Artistic-2.0",
    "Zlib", "BSL-1.0", "Unlicense", "0BSD", "NCSA", "PostgreSQL",
    "GPL-2.0-or-later", "GPL-3.0-or-later",
]);

// ─── Compatibility matrix ──────────────────────────
type Compat = "ok" | "warn" | "fail";
const COMPAT_MATRIX: Record<string, Record<string, Compat>> = {
    "MIT": { "MIT": "ok", "Apache-2.0": "ok", "BSD-2-Clause": "ok", "GPL-2.0-only": "ok", "GPL-3.0-only": "ok", "LGPL-2.1-only": "ok", "AGPL-3.0-only": "warn", "MPL-2.0": "ok" },
    "Apache-2.0": { "MIT": "ok", "Apache-2.0": "ok", "BSD-2-Clause": "ok", "GPL-2.0-only": "fail", "GPL-3.0-only": "ok", "LGPL-2.1-only": "ok", "AGPL-3.0-only": "warn", "MPL-2.0": "ok" },
    "GPL-2.0-only": { "MIT": "ok", "Apache-2.0": "fail", "BSD-2-Clause": "ok", "GPL-2.0-only": "ok", "GPL-3.0-only": "fail", "LGPL-2.1-only": "ok", "AGPL-3.0-only": "fail", "MPL-2.0": "fail" },
    "GPL-3.0-only": { "MIT": "ok", "Apache-2.0": "ok", "BSD-2-Clause": "ok", "GPL-2.0-only": "fail", "GPL-3.0-only": "ok", "LGPL-2.1-only": "ok", "AGPL-3.0-only": "ok", "MPL-2.0": "ok" },
    "AGPL-3.0-only": { "MIT": "warn", "Apache-2.0": "warn", "BSD-2-Clause": "warn", "GPL-2.0-only": "fail", "GPL-3.0-only": "ok", "LGPL-2.1-only": "warn", "AGPL-3.0-only": "ok", "MPL-2.0": "warn" },
};

// ─── License expression parser ─────────────────────
interface ExprNode {
    type: "license" | "and" | "or" | "with";
    value?: string;
    left?: ExprNode;
    right?: ExprNode;
}

function parseExpression(expr: string): ExprNode {
    const trimmed = expr.trim();
    // OR (lowest precedence)
    const orIdx = findOperator(trimmed, " OR ");
    if (orIdx >= 0) {
        return { type: "or", left: parseExpression(trimmed.slice(0, orIdx)), right: parseExpression(trimmed.slice(orIdx + 4)) };
    }
    // AND
    const andIdx = findOperator(trimmed, " AND ");
    if (andIdx >= 0) {
        return { type: "and", left: parseExpression(trimmed.slice(0, andIdx)), right: parseExpression(trimmed.slice(andIdx + 5)) };
    }
    // WITH
    const withIdx = findOperator(trimmed, " WITH ");
    if (withIdx >= 0) {
        return { type: "with", left: parseExpression(trimmed.slice(0, withIdx)), right: parseExpression(trimmed.slice(withIdx + 6)) };
    }
    // Parentheses
    if (trimmed.startsWith("(") && trimmed.endsWith(")")) {
        return parseExpression(trimmed.slice(1, -1));
    }
    return { type: "license", value: trimmed };
}

function findOperator(s: string, op: string): number {
    let depth = 0;
    for (let i = 0; i < s.length; i++) {
        if (s[i] === "(") depth++;
        else if (s[i] === ")") depth--;
        else if (depth === 0 && s.substring(i, i + op.length) === op) return i;
    }
    return -1;
}

function ExprTree({ node, depth = 0 }: { node: ExprNode; depth?: number }) {
    if (node.type === "license") {
        const isCopyleft = node.value ? COPYLEFT[node.value] : false;
        const isPerm = node.value ? PERMISSIVE.has(node.value) : false;
        return (
            <span className={`lic-expr-leaf ${isCopyleft ? "lic-expr-copyleft" : ""} ${isPerm ? "lic-expr-permissive" : ""}`}>
                {node.value}
            </span>
        );
    }
    const opLabel = node.type === "or" ? "OR" : node.type === "and" ? "AND" : "WITH";
    return (
        <span className="lic-expr-group">
            <span className="lic-expr-paren">(</span>
            <ExprTree node={node.left!} depth={depth + 1} />
            <span className={`lic-expr-op lic-expr-op-${node.type}`}>{opLabel}</span>
            <ExprTree node={node.right!} depth={depth + 1} />
            <span className="lic-expr-paren">)</span>
        </span>
    );
}

// ─── Types ─────────────────────────────────────────
interface BomComponent {
    name?: string; group?: string; version?: string; type?: string;
    licenses?: { license?: { id?: string; name?: string }; expression?: string }[];
}

interface LicenseInfo {
    id: string;
    count: number;
    category: "permissive" | "copyleft-weak" | "copyleft-strong" | "copyleft-network" | "unknown";
    osiApproved: boolean;
    components: string[];
}

// ─── Main Component ────────────────────────────────
export default function LicenseIntelligence() {
    const [licenses, setLicenses] = useState<LicenseInfo[]>([]);
    const [expressions, setExpressions] = useState<string[]>([]);
    const [osiFilter, setOsiFilter] = useState(false);
    const [selectedLic, setSelectedLic] = useState<string | null>(null);
    const [licenseText, setLicenseText] = useState("");

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select BOM file",
        });
        if (!f) return;

        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom = JSON.parse(content);
        const components: BomComponent[] = bom.components || [];

        const licMap = new Map<string, LicenseInfo>();
        const exprSet = new Set<string>();

        for (const c of components) {
            const compName = c.group ? `${c.group}/${c.name}` : (c.name || "?");
            const lics = c.licenses || [];
            if (lics.length === 0) {
                const info = licMap.get("(none)") || { id: "(none)", count: 0, category: "unknown" as const, osiApproved: false, components: [] };
                info.count++;
                info.components.push(`${compName}@${c.version || "?"}`);
                licMap.set("(none)", info);
            }
            for (const l of lics) {
                if (l.expression) {
                    exprSet.add(l.expression);
                }
                const id = l.license?.id || l.license?.name || l.expression || "unknown";
                const copyleftType = COPYLEFT[id];
                const category: LicenseInfo["category"] = copyleftType === "strong" ? "copyleft-strong"
                    : copyleftType === "weak" ? "copyleft-weak"
                        : copyleftType === "network" ? "copyleft-network"
                            : PERMISSIVE.has(id) ? "permissive" : "unknown";

                const info = licMap.get(id) || { id, count: 0, category, osiApproved: OSI_APPROVED.has(id), components: [] };
                info.count++;
                info.components.push(`${compName}@${c.version || "?"}`);
                licMap.set(id, info);
            }
        }

        setLicenses([...licMap.values()].sort((a, b) => b.count - a.count));
        setExpressions([...exprSet]);
    }, []);

    const fetchLicenseText = useCallback(async (licId: string) => {
        setSelectedLic(licId);
        setLicenseText("");
        if (licId === "(none)" || licId === "unknown") return;
        try {
            setLicenseText(`License: ${licId}\n\nFull text available at:\nhttps://spdx.org/licenses/${licId}.html\nhttps://opensource.org/licenses/${licId}`);
        } catch {
            setLicenseText("Failed to load license text");
        }
    }, []);

    // Risk score
    const risk = useMemo(() => {
        if (licenses.length === 0) return null;
        const total = licenses.reduce((s, l) => s + l.count, 0);
        const permissive = licenses.filter(l => l.category === "permissive").reduce((s, l) => s + l.count, 0);
        const copyleft = licenses.filter(l => l.category.startsWith("copyleft")).reduce((s, l) => s + l.count, 0);
        const unknown = licenses.filter(l => l.category === "unknown").reduce((s, l) => s + l.count, 0);
        return {
            permissivePct: Math.round((permissive / total) * 100),
            copyleftPct: Math.round((copyleft / total) * 100),
            unknownPct: Math.round((unknown / total) * 100),
            score: permissive === total ? "A" : copyleft === 0 && unknown <= total * 0.1 ? "A" :
                copyleft <= total * 0.05 ? "B" : copyleft <= total * 0.15 ? "C" : "D",
            permissive, copyleft, unknown, total,
        };
    }, [licenses]);

    const filtered = useMemo(() =>
        osiFilter ? licenses.filter(l => l.osiApproved) : licenses,
        [licenses, osiFilter]);

    // Compatibility matrix keys
    const matrixKeys = useMemo(() => {
        const existing = new Set(licenses.map(l => l.id));
        return Object.keys(COMPAT_MATRIX).filter(k => existing.has(k));
    }, [licenses]);

    const CATEGORY_COLORS: Record<string, string> = {
        "permissive": "#22c55e",
        "copyleft-weak": "#f59e0b",
        "copyleft-strong": "#ef4444",
        "copyleft-network": "#dc2626",
        "unknown": "#64748b",
    };

    return (
        <div className="lic-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">License Intelligence</h2>
                <button className="exec-btn" onClick={loadBom}>📁 Open BOM</button>
                {licenses.length > 0 && (
                    <label className="lic-osi-toggle">
                        <input type="checkbox" checked={osiFilter} onChange={e => setOsiFilter(e.target.checked)} />
                        OSI Approved Only
                    </label>
                )}
            </div>

            {risk && (
                <div className="lic-content fade-in">
                    {/* Risk Score */}
                    <div className="analyze-stats">
                        <div className={`analyze-stat-card lic-risk-${risk.score}`}>
                            <span className="analyze-stat-value">{risk.score}</span>
                            <span className="analyze-stat-label">Risk Score</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value" style={{ color: "#22c55e" }}>{risk.permissivePct}%</span>
                            <span className="analyze-stat-label">Permissive ({risk.permissive})</span>
                        </div>
                        <div className={`analyze-stat-card ${risk.copyleft > 0 ? "analyze-stat-warn" : ""}`}>
                            <span className="analyze-stat-value" style={{ color: risk.copyleft > 0 ? "#ef4444" : "#22c55e" }}>{risk.copyleftPct}%</span>
                            <span className="analyze-stat-label">Copyleft ({risk.copyleft})</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value" style={{ color: "#64748b" }}>{risk.unknownPct}%</span>
                            <span className="analyze-stat-label">Unknown ({risk.unknown})</span>
                        </div>
                    </div>

                    {/* Risk bar */}
                    <div className="lic-risk-bar">
                        <div className="lic-risk-seg" style={{ width: `${risk.permissivePct}%`, background: "#22c55e" }} title="Permissive" />
                        <div className="lic-risk-seg" style={{ width: `${risk.copyleftPct}%`, background: "#ef4444" }} title="Copyleft" />
                        <div className="lic-risk-seg" style={{ width: `${risk.unknownPct}%`, background: "#64748b" }} title="Unknown" />
                    </div>

                    {/* License table */}
                    <div className="lic-table-wrap">
                        <table className="lic-table">
                            <thead>
                                <tr>
                                    <th>License</th>
                                    <th>Count</th>
                                    <th>Category</th>
                                    <th>OSI</th>
                                    <th>Info</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filtered.map(l => (
                                    <tr key={l.id} className={selectedLic === l.id ? "lic-row-active" : ""}>
                                        <td>
                                            <span className="lic-id">{l.id}</span>
                                            {COPYLEFT[l.id] && <span className={`lic-badge lic-badge-${COPYLEFT[l.id]}`}>{COPYLEFT[l.id]}</span>}
                                        </td>
                                        <td><span className="lic-count">{l.count}</span></td>
                                        <td><span className="lic-cat-dot" style={{ background: CATEGORY_COLORS[l.category] }} />{l.category}</td>
                                        <td>{l.osiApproved ? "✅" : "—"}</td>
                                        <td><button className="lic-info-btn" onClick={() => fetchLicenseText(l.id)}>ℹ️</button></td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    {/* Compatibility matrix */}
                    {matrixKeys.length > 1 && (
                        <div className="lic-matrix-wrap">
                            <h4>⚖️ Compatibility Matrix</h4>
                            <table className="lic-matrix">
                                <thead>
                                    <tr>
                                        <th></th>
                                        {matrixKeys.map(k => <th key={k}>{k.replace(/-only|-or-later/g, "")}</th>)}
                                    </tr>
                                </thead>
                                <tbody>
                                    {matrixKeys.map(row => (
                                        <tr key={row}>
                                            <td className="lic-matrix-header">{row.replace(/-only|-or-later/g, "")}</td>
                                            {matrixKeys.map(col => {
                                                const c = COMPAT_MATRIX[row]?.[col] || "ok";
                                                return <td key={col} className={`lic-matrix-cell lic-compat-${c}`}>
                                                    {c === "ok" ? "✅" : c === "warn" ? "⚠️" : "❌"}
                                                </td>;
                                            })}
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}

                    {/* Expression trees */}
                    {expressions.length > 0 && (
                        <div className="lic-expressions">
                            <h4>🌳 License Expressions ({expressions.length})</h4>
                            {expressions.slice(0, 10).map((expr, i) => (
                                <div key={i} className="lic-expr-row">
                                    <code className="lic-expr-raw">{expr}</code>
                                    <div className="lic-expr-tree">
                                        <ExprTree node={parseExpression(expr)} />
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}

                    {/* License text */}
                    {selectedLic && licenseText && (
                        <div className="crypto-result crypto-result-ok fade-in">
                            <div className="crypto-result-header">📜 {selectedLic}</div>
                            <pre className="crypto-result-text">{licenseText}</pre>
                        </div>
                    )}
                </div>
            )}

            {licenses.length === 0 && (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">🏷️</span>
                    <h3>License Intelligence</h3>
                    <p>Open a BOM to analyze license risk, compatibility, copyleft exposure, and SPDX expressions</p>
                </div>
            )}
        </div>
    );
}
