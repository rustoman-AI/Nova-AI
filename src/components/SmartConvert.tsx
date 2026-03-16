import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";

interface ExecResult {
    success: boolean;
    exit_code: number;
    stdout: string;
    stderr: string;
    tool: string;
}

type ConvertFormat = "xml" | "json" | "protobuf" | "csv" | "spdxjson";

const FORMATS: { id: ConvertFormat; label: string; ext: string; icon: string }[] = [
    { id: "xml", label: "CycloneDX XML", ext: ".xml", icon: "📰" },
    { id: "json", label: "CycloneDX JSON", ext: ".json", icon: "📋" },
    { id: "protobuf", label: "CycloneDX Protobuf", ext: ".cdx", icon: "⚡" },
    { id: "csv", label: "CSV", ext: ".csv", icon: "📊" },
    { id: "spdxjson", label: "SPDX JSON", ext: ".spdx.json", icon: "🔄" },
];

const SPEC_VERSIONS = ["1.6", "1.5", "1.4", "1.3", "1.2", "1.1", "1.0"];

function detectFormat(path: string): ConvertFormat | null {
    const low = path.toLowerCase();
    if (low.endsWith(".spdx.json")) return "spdxjson";
    if (low.endsWith(".xml")) return "xml";
    if (low.endsWith(".json")) return "json";
    if (low.endsWith(".cdx") || low.endsWith(".bin")) return "protobuf";
    if (low.endsWith(".csv")) return "csv";
    return null;
}

export default function SmartConvert() {
    const [inputPath, setInputPath] = useState("");
    const [outputFormat, setOutputFormat] = useState<ConvertFormat>("json");
    const [specVersion, setSpecVersion] = useState("1.6");
    const [isRunning, setIsRunning] = useState(false);
    const [result, setResult] = useState<ExecResult | null>(null);

    const inputFormat = useMemo(() => inputPath ? detectFormat(inputPath) : null, [inputPath]);

    const pickInput = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "BOM files", extensions: ["json", "xml", "cdx", "bin", "csv", "spdx.json"] }],
            title: "Source BOM",
        });
        if (f) {
            setInputPath(f as string);
            setResult(null);
            // Auto-suggest opposite format
            const det = detectFormat(f as string);
            if (det === "json") setOutputFormat("xml");
            else if (det === "xml") setOutputFormat("json");
            else if (det === "spdxjson") setOutputFormat("json");
        }
    }, []);

    const handleConvert = useCallback(async () => {
        if (!inputPath) return;
        const fmt = FORMATS.find(f => f.id === outputFormat)!;
        const baseName = inputPath.replace(/\.[^/.]+$/, "").replace(/\.spdx$/, "");
        const defaultOut = `${baseName}-converted${fmt.ext}`;

        const outPath = await save({
            defaultPath: defaultOut,
            filters: [{ name: fmt.label, extensions: [fmt.ext.replace(".", "")] }],
        });
        if (!outPath) return;

        setIsRunning(true);
        setResult(null);

        const args = [
            "convert",
            "--input-file", inputPath,
            "--output-file", outPath,
            "--output-format", outputFormat,
        ];
        if (inputFormat) args.push("--input-format", inputFormat);
        if (outputFormat !== "csv" && outputFormat !== "spdxjson") {
            args.push("--output-version", `v${specVersion}`);
        }

        try {
            const res = await invoke<ExecResult>("run_sidecar", { name: "cyclonedx", args });
            setResult(res);
        } catch (err: any) {
            setResult({ success: false, exit_code: -1, stdout: "", stderr: String(err), tool: "cyclonedx" });
        }
        setIsRunning(false);
    }, [inputPath, outputFormat, inputFormat, specVersion]);

    const availableTargets = useMemo(() =>
        FORMATS.filter(f => f.id !== inputFormat),
        [inputFormat]);

    return (
        <div className="convert-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">Smart Convert</h2>
            </div>

            <div className="crypto-card">
                {/* Source */}
                <div className="convert-source-row">
                    <div className="convert-source">
                        <label className="settings-label">Source BOM</label>
                        <button className="diff-pick-btn" onClick={pickInput} style={{ minWidth: 200 }}>
                            📁 {inputPath ? inputPath.split("/").pop() : "Select file..."}
                        </button>
                        {inputFormat && (
                            <span className={`convert-badge convert-badge-${inputFormat}`}>
                                {FORMATS.find(f => f.id === inputFormat)?.label || inputFormat}
                            </span>
                        )}
                    </div>

                    <div className="convert-arrow">→</div>

                    <div className="convert-target">
                        <label className="settings-label">Target Format</label>
                        <div className="convert-format-grid">
                            {availableTargets.map(f => (
                                <button
                                    key={f.id}
                                    className={`crypto-mode-btn ${outputFormat === f.id ? "crypto-mode-active" : ""}`}
                                    onClick={() => setOutputFormat(f.id)}
                                >
                                    <span>{f.icon}</span>
                                    <span>{f.label}</span>
                                </button>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Spec version */}
                {outputFormat !== "csv" && outputFormat !== "spdxjson" && (
                    <div className="convert-spec-row">
                        <label className="settings-label">Spec Version</label>
                        <div className="convert-spec-pills">
                            {SPEC_VERSIONS.map(v => (
                                <button
                                    key={v}
                                    className={`convert-spec-pill ${specVersion === v ? "convert-spec-active" : ""}`}
                                    onClick={() => setSpecVersion(v)}
                                >
                                    v{v}
                                </button>
                            ))}
                        </div>
                    </div>
                )}

                {/* SPDX info */}
                {(inputFormat === "spdxjson" || outputFormat === "spdxjson") && (
                    <div className="convert-spdx-info">
                        ℹ️ CycloneDX CLI is one of the few open-source tools supporting bidirectional SPDX ↔ CycloneDX conversion
                    </div>
                )}

                {/* Convert button */}
                <div className="crypto-actions">
                    <button className="exec-btn" onClick={handleConvert} disabled={isRunning || !inputPath}>
                        {isRunning ? <><span className="spinner" /> Converting...</> : "🔄 Convert"}
                    </button>
                </div>
            </div>

            {/* Result */}
            {result && (
                <div className={`crypto-result fade-in ${result.success ? "crypto-result-ok" : "crypto-result-err"}`}>
                    <div className="crypto-result-header">
                        {result.success ? "✅ Conversion successful" : `❌ Failed (exit ${result.exit_code})`}
                    </div>
                    {result.stdout.trim() && <pre className="crypto-result-text">{result.stdout.trim()}</pre>}
                    {result.stderr.trim() && <pre className="crypto-result-text crypto-result-stderr">{result.stderr.trim()}</pre>}
                </div>
            )}

            {!inputPath && (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">🔄</span>
                    <h3>Smart BOM Converter</h3>
                    <p>Convert between CycloneDX XML/JSON/Protobuf/CSV and SPDX JSON with auto-format detection</p>
                </div>
            )}
        </div>
    );
}
