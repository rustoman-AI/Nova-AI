import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";

interface ExecResult {
    success: boolean;
    exit_code: number;
    stdout: string;
    stderr: string;
    tool: string;
}

export default function AddFilesPanel() {
    const [basePath, setBasePath] = useState("");
    const [inputBom, setInputBom] = useState("");
    const [outputBom, setOutputBom] = useState("");
    const [includeGlob, setIncludeGlob] = useState("**/**");
    const [excludeGlob, setExcludeGlob] = useState("");
    const [noInput, setNoInput] = useState(false);
    const [isRunning, setIsRunning] = useState(false);
    const [result, setResult] = useState<ExecResult | null>(null);

    const selectBaseDir = useCallback(async () => {
        const dir = await open({ directory: true, multiple: false, title: "Base directory" });
        if (dir) setBasePath(dir as string);
    }, []);

    const selectInputBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json", "xml"] }],
            title: "Existing BOM (optional)",
        });
        if (f) { setInputBom(f as string); setNoInput(false); }
    }, []);

    const selectOutputPath = useCallback(async () => {
        const f = await save({
            defaultPath: basePath ? `${basePath}/bom-with-files.json` : "bom-with-files.json",
            filters: [{ name: "CycloneDX BOM", extensions: ["json", "xml"] }],
        });
        if (f) setOutputBom(f as string);
    }, [basePath]);

    const handleRun = useCallback(async () => {
        if (!basePath) return;
        setIsRunning(true);
        setResult(null);

        const args: string[] = ["add", "files", "--base-path", basePath];

        // Input
        if (noInput) {
            args.push("--no-input");
        } else if (inputBom) {
            args.push("--input-file", inputBom);
        } else {
            args.push("--no-input");
        }

        // Output
        if (outputBom) {
            args.push("--output-file", outputBom);
        }

        // Format
        const ext = outputBom?.endsWith(".xml") ? "xml" : "json";
        args.push("--output-format", ext);

        // Include
        if (includeGlob) {
            for (const pat of includeGlob.split(",").map(s => s.trim()).filter(Boolean)) {
                args.push("--include", pat);
            }
        }

        // Exclude
        if (excludeGlob) {
            for (const pat of excludeGlob.split(",").map(s => s.trim()).filter(Boolean)) {
                args.push("--exclude", pat);
            }
        }

        try {
            const res = await invoke<ExecResult>("run_sidecar", { name: "cyclonedx", args });
            setResult(res);
        } catch (err: any) {
            setResult({ success: false, exit_code: -1, stdout: "", stderr: String(err), tool: "cyclonedx" });
        }
        setIsRunning(false);
    }, [basePath, inputBom, outputBom, noInput, includeGlob, excludeGlob]);

    return (
        <div className="addfiles-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">Add Files to BOM</h2>
            </div>

            <div className="crypto-card">
                <h3>📁 Add files with automatic hash calculation</h3>
                <p className="nist_ssdf-hint">
                    Scans directory with Ant glob patterns, computes SHA-1/256/384/512 hashes for each file, and adds them as CycloneDX File components
                </p>

                <div className="crypto-fields">
                    {/* Base directory */}
                    <div className="crypto-field">
                        <label className="settings-label">Base Directory *</label>
                        <button className="diff-pick-btn" onClick={selectBaseDir}>
                            📁 {basePath ? basePath : "Select..."}
                        </button>
                    </div>

                    {/* Input BOM */}
                    <div className="crypto-field">
                        <label className="settings-label">
                            Input BOM (optional)
                            <label style={{ marginLeft: 12, fontSize: "0.72rem", color: "var(--text-muted)" }}>
                                <input
                                    type="checkbox"
                                    checked={noInput}
                                    onChange={(e) => { setNoInput(e.target.checked); if (e.target.checked) setInputBom(""); }}
                                    style={{ marginRight: 4 }}
                                />
                                Create new BOM
                            </label>
                        </label>
                        {!noInput && (
                            <button className="diff-pick-btn" onClick={selectInputBom}>
                                📄 {inputBom ? inputBom.split("/").pop() : "Select existing BOM..."}
                            </button>
                        )}
                    </div>

                    {/* Output BOM */}
                    <div className="crypto-field">
                        <label className="settings-label">Output BOM *</label>
                        <button className="diff-pick-btn" onClick={selectOutputPath}>
                            💾 {outputBom ? outputBom.split("/").pop() : "Select output path..."}
                        </button>
                    </div>

                    {/* Glob patterns */}
                    <div className="crypto-field">
                        <label className="settings-label">Include patterns (comma-separated Ant globs)</label>
                        <input
                            type="text"
                            className="settings-input"
                            value={includeGlob}
                            onChange={(e) => setIncludeGlob(e.target.value)}
                            placeholder="**/**"
                        />
                    </div>

                    <div className="crypto-field">
                        <label className="settings-label">Exclude patterns (optional)</label>
                        <input
                            type="text"
                            className="settings-input"
                            value={excludeGlob}
                            onChange={(e) => setExcludeGlob(e.target.value)}
                            placeholder="**/node_modules/**, **/.git/**"
                        />
                    </div>
                </div>

                <div className="crypto-actions">
                    <button className="exec-btn" onClick={handleRun} disabled={isRunning || !basePath || !outputBom}>
                        {isRunning ? <><span className="spinner" /> Adding files...</> : "📁 Add Files to BOM"}
                    </button>
                </div>

                {/* Preview of command */}
                {basePath && (
                    <div className="nist_ssdf-bom-path" style={{ marginTop: 12, fontSize: "0.68rem" }}>
                        cyclonedx add files --base-path {basePath}
                        {noInput ? " --no-input" : inputBom ? ` --input-file ${inputBom.split("/").pop()}` : " --no-input"}
                        {outputBom ? ` --output-file ${outputBom.split("/").pop()}` : ""}
                        {includeGlob ? ` --include ${includeGlob}` : ""}
                        {excludeGlob ? ` --exclude ${excludeGlob}` : ""}
                    </div>
                )}
            </div>

            {/* Result */}
            {result && (
                <div className={`crypto-result fade-in ${result.success ? "crypto-result-ok" : "crypto-result-err"}`}>
                    <div className="crypto-result-header">
                        {result.success ? "✅ Files added successfully" : `❌ Failed (exit ${result.exit_code})`}
                    </div>
                    {result.stdout.trim() && <pre className="crypto-result-text">{result.stdout.trim()}</pre>}
                    {result.stderr.trim() && <pre className="crypto-result-text crypto-result-stderr">{result.stderr.trim()}</pre>}
                </div>
            )}

            {!result && !basePath && (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">📁</span>
                    <h3>Add Files to BOM</h3>
                    <p>Select a directory to scan files and add them to a CycloneDX BOM with SHA-1/256/384/512 hashes</p>
                </div>
            )}
        </div>
    );
}
