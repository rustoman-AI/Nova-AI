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

type CryptoMode = "keygen" | "sign-bom" | "sign-file" | "verify-all" | "verify-file";

const MODES: { id: CryptoMode; label: string; icon: string }[] = [
    { id: "keygen", label: "KeyGen", icon: "🔑" },
    { id: "sign-bom", label: "Sign BOM", icon: "✍️" },
    { id: "sign-file", label: "Sign File", icon: "📝" },
    { id: "verify-all", label: "Verify BOM", icon: "✅" },
    { id: "verify-file", label: "Verify File", icon: "🔍" },
];

export default function CryptoPanel() {
    const [mode, setMode] = useState<CryptoMode>("keygen");
    const [isRunning, setIsRunning] = useState(false);
    const [result, setResult] = useState<ExecResult | null>(null);

    // File state
    const [privateKey, setPrivateKey] = useState("");
    const [publicKey, setPublicKey] = useState("");
    const [bomFile, setBomFile] = useState("");
    const [targetFile, setTargetFile] = useState("");
    const [sigFile, setSigFile] = useState("");

    const pickFile = useCallback(async (title: string, exts: string[]): Promise<string | null> => {
        const f = await open({ multiple: false, title, filters: [{ name: "Files", extensions: exts }] });
        return f as string | null;
    }, []);

    const pickSavePath = useCallback(async (defaultName: string, exts: string[]): Promise<string | null> => {
        return await save({ defaultPath: defaultName, filters: [{ name: "Files", extensions: exts }] }) as string | null;
    }, []);

    const runCrypto = useCallback(async (args: string[]) => {
        setIsRunning(true);
        setResult(null);
        try {
            const res = await invoke<ExecResult>("run_sidecar", { name: "cyclonedx", args });
            setResult(res);
        } catch (err: any) {
            setResult({ success: false, exit_code: -1, stdout: "", stderr: String(err), tool: "cyclonedx" });
        }
        setIsRunning(false);
    }, []);

    // ─── Handlers ─────────────────────────────────────

    const handleKeygen = useCallback(async () => {
        const privPath = await pickSavePath("private.key", ["key", "pem"]);
        if (!privPath) return;
        const pubPath = await pickSavePath("public.key", ["key", "pem"]);
        if (!pubPath) return;
        setPrivateKey(privPath);
        setPublicKey(pubPath);
        await runCrypto(["keygen", "--private-key-file", privPath, "--public-key-file", pubPath]);
    }, [pickSavePath, runCrypto]);

    const handleSignBom = useCallback(async () => {
        if (!bomFile || !privateKey) return;
        await runCrypto(["sign", "bom", "--bom-file", bomFile, "--key-file", privateKey]);
    }, [bomFile, privateKey, runCrypto]);

    const handleSignFile = useCallback(async () => {
        if (!targetFile || !privateKey) return;
        const sigPath = sigFile || `${targetFile}.sig`;
        await runCrypto(["sign", "file", "--file", targetFile, "--key-file", privateKey, "--signature-file", sigPath]);
    }, [targetFile, privateKey, sigFile, runCrypto]);

    const handleVerifyBom = useCallback(async () => {
        if (!bomFile || !publicKey) return;
        await runCrypto(["verify", "all", "--bom-file", bomFile, "--key-file", publicKey]);
    }, [bomFile, publicKey, runCrypto]);

    const handleVerifyFile = useCallback(async () => {
        if (!targetFile || !publicKey || !sigFile) return;
        await runCrypto(["verify", "file", "--file", targetFile, "--key-file", publicKey, "--signature-file", sigFile]);
    }, [targetFile, publicKey, sigFile, runCrypto]);

    return (
        <div className="crypto-panel">
            {/* Mode selector */}
            <div className="crypto-modes">
                {MODES.map((m) => (
                    <button
                        key={m.id}
                        className={`crypto-mode-btn ${mode === m.id ? "crypto-mode-active" : ""}`}
                        onClick={() => { setMode(m.id); setResult(null); }}
                    >
                        <span>{m.icon}</span>
                        <span>{m.label}</span>
                    </button>
                ))}
            </div>

            {/* Content */}
            <div className="crypto-content">
                {/* ── KeyGen ── */}
                {mode === "keygen" && (
                    <div className="crypto-card fade-in">
                        <h3>🔑 Generate RSA Key Pair</h3>
                        <p className="nist_ssdf-hint">Generates RSA 2048-bit key pair in PEM format (PKCS#8 private, SubjectPublicKeyInfo public)</p>
                        <div className="crypto-actions">
                            <button className="exec-btn" onClick={handleKeygen} disabled={isRunning}>
                                {isRunning ? <><span className="spinner" /> Generating...</> : "🔑 Generate Keys"}
                            </button>
                        </div>
                        {privateKey && <div className="nist_ssdf-bom-path">🔒 {privateKey}</div>}
                        {publicKey && <div className="nist_ssdf-bom-path">🔓 {publicKey}</div>}
                    </div>
                )}

                {/* ── Sign BOM ── */}
                {mode === "sign-bom" && (
                    <div className="crypto-card fade-in">
                        <h3>✍️ Sign XML BOM (Enveloped XML DSig)</h3>
                        <p className="nist_ssdf-hint">Adds an enveloped XML DSig signature to XML BOM using RSA private key</p>
                        <div className="crypto-fields">
                            <FilePick label="XML BOM file" value={bomFile} onPick={async () => {
                                const f = await pickFile("Select XML BOM", ["xml"]); if (f) setBomFile(f);
                            }} />
                            <FilePick label="Private key (.pem)" value={privateKey} onPick={async () => {
                                const f = await pickFile("Select private key", ["key", "pem"]); if (f) setPrivateKey(f);
                            }} />
                        </div>
                        <div className="crypto-actions">
                            <button className="exec-btn" onClick={handleSignBom} disabled={isRunning || !bomFile || !privateKey}>
                                {isRunning ? <><span className="spinner" /> Signing...</> : "✍️ Sign BOM"}
                            </button>
                        </div>
                    </div>
                )}

                {/* ── Sign File ── */}
                {mode === "sign-file" && (
                    <div className="crypto-card fade-in">
                        <h3>📝 Sign File (Detached PKCS#1 RSA SHA-256)</h3>
                        <p className="nist_ssdf-hint">Creates a detached .sig signature file using RSA private key</p>
                        <div className="crypto-fields">
                            <FilePick label="File to sign" value={targetFile} onPick={async () => {
                                const f = await pickFile("Select file", ["*"]); if (f) setTargetFile(f);
                            }} />
                            <FilePick label="Private key (.pem)" value={privateKey} onPick={async () => {
                                const f = await pickFile("Select private key", ["key", "pem"]); if (f) setPrivateKey(f);
                            }} />
                            <FilePick label="Signature output (.sig)" value={sigFile} onPick={async () => {
                                const f = await pickSavePath("signature.sig", ["sig"]); if (f) setSigFile(f);
                            }} />
                        </div>
                        <div className="crypto-actions">
                            <button className="exec-btn" onClick={handleSignFile} disabled={isRunning || !targetFile || !privateKey}>
                                {isRunning ? <><span className="spinner" /> Signing...</> : "📝 Sign File"}
                            </button>
                        </div>
                    </div>
                )}

                {/* ── Verify BOM ── */}
                {mode === "verify-all" && (
                    <div className="crypto-card fade-in">
                        <h3>✅ Verify XML BOM Signatures</h3>
                        <p className="nist_ssdf-hint">Verifies all XML DSig signatures embedded in the XML BOM</p>
                        <div className="crypto-fields">
                            <FilePick label="Signed XML BOM" value={bomFile} onPick={async () => {
                                const f = await pickFile("Select signed XML BOM", ["xml"]); if (f) setBomFile(f);
                            }} />
                            <FilePick label="Public key (.pem)" value={publicKey} onPick={async () => {
                                const f = await pickFile("Select public key", ["key", "pem"]); if (f) setPublicKey(f);
                            }} />
                        </div>
                        <div className="crypto-actions">
                            <button className="exec-btn" onClick={handleVerifyBom} disabled={isRunning || !bomFile || !publicKey}>
                                {isRunning ? <><span className="spinner" /> Verifying...</> : "✅ Verify BOM"}
                            </button>
                        </div>
                    </div>
                )}

                {/* ── Verify File ── */}
                {mode === "verify-file" && (
                    <div className="crypto-card fade-in">
                        <h3>🔍 Verify File Signature</h3>
                        <p className="nist_ssdf-hint">Verifies a detached PKCS#1 RSA SHA-256 .sig signature</p>
                        <div className="crypto-fields">
                            <FilePick label="Original file" value={targetFile} onPick={async () => {
                                const f = await pickFile("Select file", ["*"]); if (f) setTargetFile(f);
                            }} />
                            <FilePick label="Signature (.sig)" value={sigFile} onPick={async () => {
                                const f = await pickFile("Select signature", ["sig"]); if (f) setSigFile(f);
                            }} />
                            <FilePick label="Public key (.pem)" value={publicKey} onPick={async () => {
                                const f = await pickFile("Select public key", ["key", "pem"]); if (f) setPublicKey(f);
                            }} />
                        </div>
                        <div className="crypto-actions">
                            <button className="exec-btn" onClick={handleVerifyFile} disabled={isRunning || !targetFile || !publicKey || !sigFile}>
                                {isRunning ? <><span className="spinner" /> Verifying...</> : "🔍 Verify File"}
                            </button>
                        </div>
                    </div>
                )}

                {/* Result */}
                {result && (
                    <div className={`crypto-result fade-in ${result.success ? "crypto-result-ok" : "crypto-result-err"}`}>
                        <div className="crypto-result-header">
                            {result.success ? "✅ Success" : `❌ Failed (exit ${result.exit_code})`}
                        </div>
                        {result.stdout.trim() && <pre className="crypto-result-text">{result.stdout.trim()}</pre>}
                        {result.stderr.trim() && <pre className="crypto-result-text crypto-result-stderr">{result.stderr.trim()}</pre>}
                    </div>
                )}
            </div>
        </div>
    );
}

function FilePick({ label, value, onPick }: { label: string; value: string; onPick: () => void }) {
    return (
        <div className="crypto-field">
            <label className="settings-label">{label}</label>
            <button className="diff-pick-btn" onClick={onPick}>
                📁 {value ? value.split("/").pop() : "Select..."}
            </button>
        </div>
    );
}
