import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

interface Rule {
    id: string;
    name: string;
    description: string;
    severity: "error" | "warning" | "info";
    field: string;
    operator: string;
    threshold?: number;
    pattern?: string;
}

interface RuleResult {
    rule_id: string;
    rule_name: string;
    severity: "error" | "warning" | "info";
    passed: boolean;
    message: string;
    actual_value: string;
}

interface EvaluationReport {
    total: number;
    passed: number;
    failed: number;
    results: RuleResult[];
}

const SEV_COLORS: Record<string, string> = { error: "#ff4d4f", warning: "#faad14", info: "#1890ff" };
const SEV_ICONS: Record<string, string> = { error: "❌", warning: "⚠️", info: "ℹ️" };

export default function RulesPanel() {
    const [rules, setRules] = useState<Rule[]>([]);
    const [report, setReport] = useState<EvaluationReport | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [fileName, setFileName] = useState("");

    useEffect(() => {
        invoke<Rule[]>("load_rules").then(setRules).catch(() => { });
    }, []);

    const handleEvaluate = useCallback(async () => {
        try {
            const file = await open({
                title: "Select SBOM to evaluate",
                filters: [{ name: "JSON", extensions: ["json"] }],
            });
            if (!file) return;
            setLoading(true);
            setError("");
            setFileName(String(file).split("/").pop() || String(file));
            const result = await invoke<EvaluationReport>("evaluate_rules", { sbomPath: String(file) });
            setReport(result);
        } catch (e) {
            setError(String(e));
        }
        setLoading(false);
    }, []);

    const score = report ? Math.round((report.passed / report.total) * 100) : 0;
    const scoreColor = score >= 80 ? "#52c41a" : score >= 50 ? "#faad14" : "#ff4d4f";

    return (
        <div style={{ padding: "24px", maxWidth: 1100, margin: "0 auto" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 24 }}>
                <h2 style={{ margin: 0, fontSize: 22 }}>📏 Rules Engine</h2>
                <button onClick={handleEvaluate} disabled={loading} className="rules-btn rules-btn-primary">
                    {loading ? "⏳ Evaluating..." : "🔍 Evaluate SBOM"}
                </button>
                {fileName && <span style={{ fontSize: 13, color: "#8c8c8c", fontFamily: "monospace" }}>{fileName}</span>}
            </div>

            {error && <div className="rules-error">{error}</div>}

            {report && (
                <div className="rules-summary-row">
                    <div className="rules-card" style={{ borderColor: scoreColor }}>
                        <div className="rules-card-label">Score</div>
                        <div className="rules-card-value" style={{ color: scoreColor }}>{score}%</div>
                    </div>
                    <div className="rules-card" style={{ borderColor: "#52c41a" }}>
                        <div className="rules-card-label">Passed</div>
                        <div className="rules-card-value" style={{ color: "#52c41a" }}>{report.passed}</div>
                    </div>
                    <div className="rules-card" style={{ borderColor: "#ff4d4f" }}>
                        <div className="rules-card-label">Failed</div>
                        <div className="rules-card-value" style={{ color: "#ff4d4f" }}>{report.failed}</div>
                    </div>
                    <div className="rules-card">
                        <div className="rules-card-label">Total</div>
                        <div className="rules-card-value">{report.total}</div>
                    </div>
                </div>
            )}

            {report && (
                <div className="rules-table-wrap">
                    <table className="rules-table">
                        <thead>
                            <tr>
                                <th style={{ width: 40 }}>✓</th>
                                <th style={{ width: 50 }}>Sev</th>
                                <th style={{ width: 120 }}>Rule ID</th>
                                <th style={{ width: 200 }}>Name</th>
                                <th>Result</th>
                                <th style={{ width: 100 }}>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            {report.results.map((r) => (
                                <tr key={r.rule_id} className={`rules-row ${r.passed ? "rules-row-pass" : "rules-row-fail"}`}>
                                    <td>{r.passed ? "✅" : "❌"}</td>
                                    <td><span style={{ color: SEV_COLORS[r.severity] }}>{SEV_ICONS[r.severity]}</span></td>
                                    <td><code className="rules-rule-id">{r.rule_id}</code></td>
                                    <td>{r.rule_name}</td>
                                    <td style={{ fontSize: 13 }}>{r.message}</td>
                                    <td style={{ fontFamily: "monospace", fontSize: 12, color: "#8c8c8c" }}>{r.actual_value}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}

            {/* Rules catalog */}
            <details style={{ marginTop: 24 }} open={!report}>
                <summary style={{ cursor: "pointer", fontSize: 15, color: "#b8b8cc" }}>
                    📖 Rule Catalog ({rules.length} rules)
                </summary>
                <div style={{ marginTop: 12, display: "grid", gap: 8 }}>
                    {rules.map((rule) => (
                        <div key={rule.id} className="rules-catalog-card">
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                <code className="rules-rule-id">{rule.id}</code>
                                <span className="rules-sev-badge" style={{ background: SEV_COLORS[rule.severity] + "22", color: SEV_COLORS[rule.severity] }}>
                                    {rule.severity}
                                </span>
                                <strong>{rule.name}</strong>
                            </div>
                            <div style={{ fontSize: 12, color: "#8c8c8c", marginTop: 4 }}>
                                {rule.description} — <code>{rule.field}</code> [{rule.operator}]
                                {rule.threshold != null && ` ≥${rule.threshold}`}
                                {rule.pattern && ` = "${rule.pattern}"`}
                            </div>
                        </div>
                    ))}
                </div>
            </details>

            {!report && !error && (
                <div className="rules-empty">
                    <div style={{ fontSize: 48, marginBottom: 16 }}>📏</div>
                    <div style={{ fontSize: 16, marginBottom: 8 }}>SBOM Validation Rules</div>
                    <div style={{ color: "#8c8c8c", maxWidth: 400, lineHeight: 1.6 }}>
                        Evaluate your SBOM against NIST, NTIA, and custom YAML rules. Click "Evaluate SBOM" to begin.
                    </div>
                </div>
            )}

            <style>{`
        .rules-btn {
          padding: 8px 16px; border-radius: 8px; border: 1px solid #333;
          background: #1a1a2e; color: #e0e0e0; cursor: pointer; font-size: 13px; transition: all 0.2s;
        }
        .rules-btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
        .rules-btn:disabled { opacity: 0.5; cursor: wait; }
        .rules-btn-primary { border-color: #722ed1; color: #722ed1; }
        .rules-btn-primary:hover { background: #722ed122; }
        .rules-error { padding: 12px; background: #ff4d4f18; border: 1px solid #ff4d4f44; border-radius: 8px; color: #ff7875; margin-bottom: 16px; font-size: 13px; }
        .rules-summary-row { display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
        .rules-card { flex: 1; min-width: 100px; padding: 16px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 12px; text-align: center; }
        .rules-card-label { font-size: 11px; color: #8c8c8c; text-transform: uppercase; letter-spacing: 1px; }
        .rules-card-value { font-size: 28px; font-weight: 700; margin: 4px 0; }
        .rules-table-wrap { border: 1px solid #2a2a4a; border-radius: 12px; overflow: hidden; }
        .rules-table { width: 100%; border-collapse: collapse; }
        .rules-table th { text-align: left; padding: 10px 14px; background: #16162a; color: #8c8c8c; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #2a2a4a; }
        .rules-table td { padding: 10px 14px; border-bottom: 1px solid #1a1a30; font-size: 13px; }
        .rules-row:hover { background: #ffffff06; }
        .rules-row-pass { border-left: 3px solid #52c41a; }
        .rules-row-fail { border-left: 3px solid #ff4d4f; }
        .rules-rule-id { background: #ffffff0a; padding: 2px 8px; border-radius: 4px; font-size: 12px; color: #b8b8cc; }
        .rules-sev-badge { padding: 2px 8px; border-radius: 10px; font-size: 10px; text-transform: uppercase; }
        .rules-catalog-card { padding: 10px 14px; background: #16162a; border-radius: 8px; }
        .rules-empty { text-align: center; padding: 80px 20px; color: #666; }
      `}</style>
        </div>
    );
}
