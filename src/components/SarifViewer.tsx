import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";

interface SarifResult {
    ruleId: string;
    level: "error" | "warning" | "note" | "none";
    message: { text: string };
    locations?: { physicalLocation?: { artifactLocation?: { uri?: string } } }[];
}

interface SarifRun {
    tool: { driver: { name: string; version: string; rules?: { id: string; name?: string; shortDescription?: { text: string } }[] } };
    results: SarifResult[];
    invocations?: { executionSuccessful: boolean }[];
    properties?: { summary?: { pass?: number; fail?: number; total?: number; score?: string } };
}

interface SarifDoc {
    version: string;
    runs: SarifRun[];
}

type LevelFilter = "all" | "error" | "warning" | "note";

const LEVEL_COLORS: Record<string, string> = {
    error: "#ff4d4f",
    warning: "#faad14",
    note: "#1890ff",
    none: "#8c8c8c",
};

const LEVEL_ICONS: Record<string, string> = {
    error: "❌",
    warning: "⚠️",
    note: "ℹ️",
    none: "○",
};

export default function SarifViewer() {
    const [sarif, setSarif] = useState<SarifDoc | null>(null);
    const [error, setError] = useState("");
    const [filter, setFilter] = useState<LevelFilter>("all");
    const [fileName, setFileName] = useState("");

    const handleOpen = useCallback(async () => {
        try {
            const file = await open({
                filters: [{ name: "SARIF", extensions: ["sarif", "sarif.json", "json"] }],
            });
            if (!file) return;

            const content = await invoke<string>("read_file_contents", { path: file });
            const parsed = JSON.parse(content) as SarifDoc;
            if (!parsed.runs || !Array.isArray(parsed.runs)) {
                throw new Error("Invalid SARIF: missing 'runs' array");
            }
            setSarif(parsed);
            setError("");
            setFileName(String(file).split("/").pop() || String(file));
        } catch (e) {
            setError(String(e));
        }
    }, []);

    const handleExport = useCallback(async () => {
        try {
            const inputFile = await open({
                title: "Select NIST compliance report",
                filters: [{ name: "JSON", extensions: ["json"] }],
            });
            if (!inputFile) return;

            const outputFile = await save({
                title: "Save SARIF report",
                defaultPath: "compliance.sarif.json",
                filters: [{ name: "SARIF", extensions: ["sarif.json", "json"] }],
            });
            if (!outputFile) return;

            const content = await invoke<string>("engine_export_sarif", {
                inputPath: String(inputFile),
                outputPath: String(outputFile),
            });
            const parsed = JSON.parse(content) as SarifDoc;
            setSarif(parsed);
            setError("");
            setFileName(String(outputFile).split("/").pop() || "exported.sarif.json");
        } catch (e) {
            setError(String(e));
        }
    }, []);

    const run = sarif?.runs?.[0];
    const results = run?.results || [];
    const filtered = filter === "all" ? results : results.filter((r) => r.level === filter);
    const summary = run?.properties?.summary;

    const counts = {
        error: results.filter((r) => r.level === "error").length,
        warning: results.filter((r) => r.level === "warning").length,
        note: results.filter((r) => r.level === "note").length,
        total: results.length,
    };

    return (
        <div style={{ padding: "24px", maxWidth: 1100, margin: "0 auto" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 24 }}>
                <h2 style={{ margin: 0, fontSize: 22, display: "flex", alignItems: "center", gap: 8 }}>
                    📊 SARIF Viewer
                </h2>
                <button onClick={handleOpen} className="sarif-btn sarif-btn-primary">
                    📂 Open SARIF
                </button>
                <button onClick={handleExport} className="sarif-btn sarif-btn-accent">
                    🔄 Export NIST → SARIF
                </button>
                {fileName && (
                    <span style={{ fontSize: 13, color: "#8c8c8c", fontFamily: "monospace" }}>{fileName}</span>
                )}
            </div>

            {error && (
                <div className="sarif-error">{error}</div>
            )}

            {sarif && run && (
                <>
                    {/* Tool info + Summary */}
                    <div className="sarif-summary-row">
                        <div className="sarif-card">
                            <div className="sarif-card-label">Tool</div>
                            <div className="sarif-card-value">{run.tool.driver.name}</div>
                            <div className="sarif-card-sub">v{run.tool.driver.version}</div>
                        </div>
                        <div className="sarif-card" style={{ borderColor: LEVEL_COLORS.error }}>
                            <div className="sarif-card-label">Errors</div>
                            <div className="sarif-card-value" style={{ color: LEVEL_COLORS.error }}>{counts.error}</div>
                        </div>
                        <div className="sarif-card" style={{ borderColor: LEVEL_COLORS.warning }}>
                            <div className="sarif-card-label">Warnings</div>
                            <div className="sarif-card-value" style={{ color: LEVEL_COLORS.warning }}>{counts.warning}</div>
                        </div>
                        <div className="sarif-card" style={{ borderColor: LEVEL_COLORS.note }}>
                            <div className="sarif-card-label">Notes</div>
                            <div className="sarif-card-value" style={{ color: LEVEL_COLORS.note }}>{counts.note}</div>
                        </div>
                        {summary?.score && (
                            <div className="sarif-card">
                                <div className="sarif-card-label">Score</div>
                                <div className="sarif-card-value">{summary.score}</div>
                            </div>
                        )}
                    </div>

                    {/* Filter bar */}
                    <div className="sarif-filter-bar">
                        {(["all", "error", "warning", "note"] as LevelFilter[]).map((lvl) => (
                            <button
                                key={lvl}
                                className={`sarif-filter-btn ${filter === lvl ? "active" : ""}`}
                                onClick={() => setFilter(lvl)}
                                style={filter === lvl && lvl !== "all" ? { borderColor: LEVEL_COLORS[lvl], color: LEVEL_COLORS[lvl] } : {}}
                            >
                                {lvl === "all" ? `All (${counts.total})` : `${LEVEL_ICONS[lvl]} ${lvl} (${counts[lvl]})`}
                            </button>
                        ))}
                    </div>

                    {/* Results table */}
                    <div className="sarif-table-wrap">
                        <table className="sarif-table">
                            <thead>
                                <tr>
                                    <th style={{ width: 40 }}>Lvl</th>
                                    <th style={{ width: 150 }}>Rule ID</th>
                                    <th>Message</th>
                                    <th style={{ width: 200 }}>Location</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filtered.map((r, i) => (
                                    <tr key={i} className={`sarif-row sarif-row-${r.level}`}>
                                        <td>
                                            <span style={{ color: LEVEL_COLORS[r.level] || "#888" }}>
                                                {LEVEL_ICONS[r.level] || "?"}
                                            </span>
                                        </td>
                                        <td>
                                            <code className="sarif-rule-id">{r.ruleId}</code>
                                        </td>
                                        <td>{r.message.text}</td>
                                        <td style={{ fontSize: 12, color: "#8c8c8c", fontFamily: "monospace" }}>
                                            {r.locations?.[0]?.physicalLocation?.artifactLocation?.uri || "—"}
                                        </td>
                                    </tr>
                                ))}
                                {filtered.length === 0 && (
                                    <tr>
                                        <td colSpan={4} style={{ textAlign: "center", padding: 24, color: "#666" }}>
                                            {filter === "all" ? "No results found" : `No ${filter} results`}
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>

                    {/* Rules reference */}
                    {run.tool.driver.rules && run.tool.driver.rules.length > 0 && (
                        <details style={{ marginTop: 16 }}>
                            <summary style={{ cursor: "pointer", color: "#8c8c8c", fontSize: 13 }}>
                                📖 Rule definitions ({run.tool.driver.rules.length})
                            </summary>
                            <div style={{ marginTop: 8, display: "grid", gap: 8 }}>
                                {run.tool.driver.rules.map((rule) => (
                                    <div key={rule.id} className="sarif-rule-card">
                                        <code>{rule.id}</code>
                                        <span style={{ marginLeft: 8 }}>{rule.shortDescription?.text || rule.name || ""}</span>
                                    </div>
                                ))}
                            </div>
                        </details>
                    )}
                </>
            )}

            {!sarif && !error && (
                <div className="sarif-empty">
                    <div style={{ fontSize: 48, marginBottom: 16 }}>📊</div>
                    <div style={{ fontSize: 16, marginBottom: 8 }}>SARIF Report Viewer</div>
                    <div style={{ color: "#8c8c8c", maxWidth: 400, lineHeight: 1.6 }}>
                        Open a SARIF 2.1.0 file to visualize security scan results, or export a NIST compliance report to SARIF format for CI/CD integration.
                    </div>
                </div>
            )}

            <style>{`
        .sarif-btn {
          padding: 8px 16px;
          border-radius: 8px;
          border: 1px solid #333;
          background: #1a1a2e;
          color: #e0e0e0;
          cursor: pointer;
          font-size: 13px;
          transition: all 0.2s;
        }
        .sarif-btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
        .sarif-btn-primary { border-color: #1890ff; color: #1890ff; }
        .sarif-btn-primary:hover { background: #1890ff22; }
        .sarif-btn-accent { border-color: #722ed1; color: #722ed1; }
        .sarif-btn-accent:hover { background: #722ed122; }

        .sarif-error {
          padding: 12px 16px;
          background: #ff4d4f18;
          border: 1px solid #ff4d4f44;
          border-radius: 8px;
          color: #ff7875;
          margin-bottom: 16px;
          font-size: 13px;
        }

        .sarif-summary-row {
          display: flex;
          gap: 12px;
          margin-bottom: 16px;
          flex-wrap: wrap;
        }

        .sarif-card {
          flex: 1;
          min-width: 120px;
          padding: 16px;
          background: #16162a;
          border: 1px solid #2a2a4a;
          border-radius: 12px;
          text-align: center;
        }
        .sarif-card-label { font-size: 11px; color: #8c8c8c; text-transform: uppercase; letter-spacing: 1px; }
        .sarif-card-value { font-size: 28px; font-weight: 700; margin: 4px 0; }
        .sarif-card-sub { font-size: 12px; color: #666; }

        .sarif-filter-bar {
          display: flex;
          gap: 8px;
          margin-bottom: 16px;
        }
        .sarif-filter-btn {
          padding: 6px 14px;
          border-radius: 20px;
          border: 1px solid #333;
          background: transparent;
          color: #999;
          cursor: pointer;
          font-size: 12px;
          transition: all 0.2s;
        }
        .sarif-filter-btn.active { background: #ffffff0a; color: #fff; border-color: #555; }
        .sarif-filter-btn:hover { border-color: #555; }

        .sarif-table-wrap {
          border: 1px solid #2a2a4a;
          border-radius: 12px;
          overflow: hidden;
        }
        .sarif-table {
          width: 100%;
          border-collapse: collapse;
        }
        .sarif-table th {
          text-align: left;
          padding: 10px 14px;
          background: #16162a;
          color: #8c8c8c;
          font-size: 11px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          border-bottom: 1px solid #2a2a4a;
        }
        .sarif-table td {
          padding: 10px 14px;
          border-bottom: 1px solid #1a1a30;
          font-size: 13px;
        }
        .sarif-row:hover { background: #ffffff06; }
        .sarif-row-error { border-left: 3px solid #ff4d4f; }
        .sarif-row-warning { border-left: 3px solid #faad14; }
        .sarif-row-note { border-left: 3px solid #1890ff; }

        .sarif-rule-id {
          background: #ffffff0a;
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 12px;
          color: #b8b8cc;
        }

        .sarif-rule-card {
          padding: 8px 12px;
          background: #16162a;
          border-radius: 8px;
          font-size: 13px;
        }

        .sarif-empty {
          text-align: center;
          padding: 80px 20px;
          color: #666;
        }
      `}</style>
        </div>
    );
}
