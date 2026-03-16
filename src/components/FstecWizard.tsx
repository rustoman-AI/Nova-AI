import { useState, useCallback, useReducer, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";

interface ExecResult {
    success: boolean;
    exit_code: number;
    stdout: string;
    stderr: string;
    tool: string;
}

interface LogEntry {
    type: "info" | "success" | "error" | "cmd";
    text: string;
    ts: number;
}

type FstecStep = "project" | "generate" | "validate" | "update" | "check" | "convert-xml" | "sign" | "verify" | "export" | "done";

const STEP_ORDER: FstecStep[] = ["project", "generate", "validate", "update", "check", "convert-xml", "sign", "verify", "export", "done"];

type WizardAction =
    | { type: "NEXT" }
    | { type: "BACK" }
    | { type: "SKIP_TO"; step: FstecStep }
    | { type: "RESET" };

function wizardReducer(state: FstecStep, action: WizardAction): FstecStep {
    switch (action.type) {
        case "NEXT": {
            const idx = STEP_ORDER.indexOf(state);
            return idx < STEP_ORDER.length - 1 ? STEP_ORDER[idx + 1] : state;
        }
        case "BACK": {
            const idx = STEP_ORDER.indexOf(state);
            return idx > 0 ? STEP_ORDER[idx - 1] : state;
        }
        case "SKIP_TO":
            return action.step;
        case "RESET":
            return "project";
        default:
            return state;
    }
}

const STEPS_META: { id: FstecStep; label: string; icon: string; description: string }[] = [
    { id: "project", label: "Проект", icon: "📁", description: "Выбрать папку проекта" },
    { id: "generate", label: "cdxgen", icon: "🔧", description: "Сгенерировать SBOM" },
    { id: "validate", label: "Валидация", icon: "✓", description: "CycloneDX validate" },
    { id: "update", label: "NIST-фикс", icon: "🏛️", description: "Стрибог + ГОСТ-поля" },
    { id: "check", label: "Проверка", icon: "🛡️", description: "sbom-checker-go check" },
    { id: "convert-xml", label: "XML", icon: "🔄", description: "JSON → XML для подписи" },
    { id: "sign", label: "Подпись", icon: "✍️", description: "XML DSig RSA" },
    { id: "verify", label: "Верификация", icon: "✅", description: "Проверка подписи" },
    { id: "export", label: "Экспорт", icon: "📊", description: "CSV / ODT отчёт" },
];

export default function FstecWizard() {
    const [step, dispatch] = useReducer(wizardReducer, "project");
    const [projectDir, setProjectDir] = useState("");
    const [outputDir, setOutputDir] = useState("");
    const [appName, setAppName] = useState("Keycloak");
    const [appVersion, setAppVersion] = useState("26.0.0");
    const [manufacturer, setManufacturer] = useState("");
    const [bomPath, setBomPath] = useState("");
    const [fixedBomPath, setFixedBomPath] = useState("");
    const [xmlBomPath, setXmlBomPath] = useState("");
    const [signedBomPath, setSignedBomPath] = useState("");
    const [keyFile, setKeyFile] = useState("");
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [isRunning, setIsRunning] = useState(false);
    const [expandedLog, setExpandedLog] = useState(true);
    const [_runId, setRunId] = useState<string | null>(null);
    const runIdRef = useRef<string | null>(null);

    // ─── Pipeline persistence helpers ───────────────
    const ensureRun = useCallback(async (): Promise<string> => {
        if (runIdRef.current) return runIdRef.current;
        const config = JSON.stringify({ appName, appVersion, manufacturer, projectDir, outputDir });
        const id = await invoke<string>("pipeline_create", {
            name: `NIST ${appName} ${appVersion}`,
            config,
        });
        runIdRef.current = id;
        setRunId(id);
        return id;
    }, [appName, appVersion, manufacturer, projectDir, outputDir]);

    const recordStep = useCallback(async (
        stepName: string, status: string, cmd: string | null,
        exitCode: number | null, stdoutStr: string | null, stderrStr: string | null,
    ) => {
        const rid = runIdRef.current;
        if (!rid) return;
        try {
            await invoke("pipeline_update_step", {
                runId: rid, stepName: stepName, status,
                command: cmd, exitCode: exitCode,
                stdout: stdoutStr?.slice(0, 5000) ?? null,
                stderr: stderrStr?.slice(0, 5000) ?? null,
            });
        } catch { /* best-effort */ }
    }, []);

    const recordArtifact = useCallback(async (filePath: string, fileType: string) => {
        const rid = runIdRef.current;
        if (!rid) return;
        try {
            await invoke("pipeline_add_artifact", {
                runId: rid, stepId: null, filePath, fileType,
            });
        } catch { /* best-effort */ }
    }, []);

    const addLog = useCallback((type: LogEntry["type"], text: string) => {
        setLogs((prev) => [...prev, { type, text, ts: Date.now() }]);
    }, []);

    const runTool = useCallback(
        async (executable: string, args: string[], label: string): Promise<ExecResult> => {
            setIsRunning(true);
            addLog("cmd", `$ ${executable} ${args.join(" ")}`);
            try {
                const res = await invoke<ExecResult>("run_external_tool", {
                    executable,
                    args,
                    toolName: label,
                    workingDir: projectDir || null,
                    envVars: null,
                });
                if (res.stdout.trim()) addLog("info", res.stdout.trim());
                if (res.stderr.trim()) addLog(res.success ? "info" : "error", res.stderr.trim());
                if (res.success) {
                    addLog("success", `✓ ${label} — успешно (exit 0)`);
                } else {
                    addLog("error", `✗ ${label} — ошибка (exit ${res.exit_code})`);
                }
                return res;
            } catch (err: any) {
                addLog("error", `✗ ${label}: ${err?.toString?.() ?? String(err)}`);
                throw err;
            } finally {
                setIsRunning(false);
            }
        },
        [addLog, projectDir]
    );

    const runSidecarCmd = useCallback(
        async (name: string, args: string[], label: string): Promise<ExecResult> => {
            setIsRunning(true);
            addLog("cmd", `$ ${name} ${args.join(" ")}`);
            try {
                const res = await invoke<ExecResult>("run_sidecar", { name, args });
                if (res.stdout.trim()) addLog("info", res.stdout.trim());
                if (res.stderr.trim()) addLog(res.success ? "info" : "error", res.stderr.trim());
                if (res.success) {
                    addLog("success", `✓ ${label} — успешно`);
                } else {
                    addLog("error", `✗ ${label} — ошибка (exit ${res.exit_code})`);
                }
                return res;
            } catch (err: any) {
                addLog("error", `✗ ${label}: ${err?.toString?.() ?? String(err)}`);
                throw err;
            } finally {
                setIsRunning(false);
            }
        },
        [addLog]
    );

    // ─── Step handlers ─────────────────────────────

    const selectProject = useCallback(async () => {
        const dir = await open({ directory: true, multiple: false, title: "Выберите папку проекта" });
        if (dir) {
            setProjectDir(dir as string);
            addLog("success", `Проект: ${dir}`);
        }
    }, [addLog]);

    const selectOutputDir = useCallback(async () => {
        const dir = await open({ directory: true, multiple: false, title: "Папка для результатов" });
        if (dir) {
            setOutputDir(dir as string);
            addLog("success", `Выходная папка: ${dir}`);
        }
    }, [addLog]);

    const selectExistingBom = useCallback(async () => {
        const file = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json", "xml"] }],
            title: "Выберите существующий BOM",
        });
        if (file) {
            setBomPath(file as string);
            addLog("success", `BOM: ${file}`);
        }
    }, [addLog]);

    const handleGenerate = useCallback(async () => {
        const outBom = `${outputDir || projectDir}/bom-cdxgen.json`;
        await ensureRun();
        const cmdStr = `npx @cyclonedx/cdxgen -t java ${projectDir} -o ${outBom} --spec-version 1.6`;
        await recordStep("generate", "running", cmdStr, null, null, null);
        try {
            const res = await runTool("npx", [
                "@cyclonedx/cdxgen",
                "-t", "java",
                projectDir,
                "-o", outBom,
                "--spec-version", "1.6",
            ], "cdxgen");
            setBomPath(outBom);
            await recordStep("generate", res.success ? "done" : "failed", cmdStr, res.exit_code, res.stdout, res.stderr);
            if (res.success) await recordArtifact(outBom, "bom-json");
            dispatch({ type: "NEXT" });
        } catch { /* logged above */ }
    }, [projectDir, outputDir, runTool, ensureRun, recordStep, recordArtifact]);

    const handleValidate = useCallback(async () => {
        await ensureRun();
        const cmdStr = `cyclonedx validate --input-file ${bomPath} --fail-on-errors`;
        await recordStep("validate", "running", cmdStr, null, null, null);
        try {
            const res = await runSidecarCmd("cyclonedx", [
                "validate",
                "--input-file", bomPath,
                "--input-format", "json",
                "--fail-on-errors",
            ], "CycloneDX validate");
            await recordStep("validate", res.success ? "done" : "failed", cmdStr, res.exit_code, res.stdout, res.stderr);
            dispatch({ type: "NEXT" });
        } catch { /* logged */ }
    }, [bomPath, runSidecarCmd, ensureRun, recordStep]);

    const handleUpdate = useCallback(async () => {
        const outDir = outputDir || projectDir;
        const fixed = `${outDir}/bom-nist_ssdf-fixed.json`;
        const args = [
            "update",
            "--app-name", appName,
            "--app-version", appVersion,
            ...(manufacturer ? ["--manufacturer", manufacturer] : []),
            "--calculate-hashes",
            "--props",
            bomPath,
            fixed,
        ];
        const cmdStr = `sbom-checker-go ${args.join(" ")}`;
        await recordStep("update", "running", cmdStr, null, null, null);
        try {
            const res = await runSidecarCmd("sbom-checker-go", args, "sbom-checker-go update");
            setFixedBomPath(fixed);
            await recordStep("update", res.success ? "done" : "failed", cmdStr, res.exit_code, res.stdout, res.stderr);
            if (res.success) await recordArtifact(fixed, "bom-fixed");
            dispatch({ type: "NEXT" });
        } catch { /* logged */ }
    }, [bomPath, appName, appVersion, manufacturer, outputDir, projectDir, runSidecarCmd, recordStep, recordArtifact]);

    const handleCheck = useCallback(async () => {
        const cmdStr = `sbom-checker-go check --validate-hashes --check-vcs ${fixedBomPath}`;
        await recordStep("check", "running", cmdStr, null, null, null);
        try {
            const res = await runSidecarCmd("sbom-checker-go", [
                "check",
                "--validate-hashes",
                "--check-vcs",
                fixedBomPath,
            ], "sbom-checker-go check");
            await recordStep("check", res.success ? "done" : "failed", cmdStr, res.exit_code, res.stdout, res.stderr);
            dispatch({ type: "NEXT" });
        } catch { /* logged */ }
    }, [fixedBomPath, runSidecarCmd, recordStep]);

    const selectKeyFile = useCallback(async () => {
        const f = await open({ multiple: false, filters: [{ name: "PEM Key", extensions: ["key", "pem"] }], title: "Выберите ключ RSA" });
        if (f) { setKeyFile(f as string); addLog("success", `Ключ: ${f}`); }
    }, [addLog]);

    const handleConvertXml = useCallback(async () => {
        const outDir = outputDir || projectDir;
        const xmlPath = `${outDir}/bom-nist_ssdf-signed.xml`;
        const cmdStr = `cyclonedx convert --input-file ${fixedBomPath} --output-file ${xmlPath} --output-format xml`;
        await recordStep("convert-xml", "running", cmdStr, null, null, null);
        try {
            const res = await runSidecarCmd("cyclonedx", [
                "convert",
                "--input-file", fixedBomPath,
                "--output-file", xmlPath,
                "--input-format", "json",
                "--output-format", "xml",
            ], "JSON → XML");
            await recordStep("convert-xml", res.success ? "done" : "failed", cmdStr, res.exit_code, res.stdout, res.stderr);
            if (res.success) {
                setXmlBomPath(xmlPath);
                await recordArtifact(xmlPath, "bom-xml");
            }
            dispatch({ type: "NEXT" });
        } catch { /* logged */ }
    }, [fixedBomPath, outputDir, projectDir, runSidecarCmd, recordStep, recordArtifact]);

    const handleSign = useCallback(async () => {
        if (!keyFile) return;
        const cmdStr = `cyclonedx sign bom --bom-file ${xmlBomPath} --key-file ${keyFile}`;
        await recordStep("sign", "running", cmdStr, null, null, null);
        try {
            const res = await runSidecarCmd("cyclonedx", [
                "sign", "bom",
                "--bom-file", xmlBomPath,
                "--key-file", keyFile,
            ], "XML DSig Sign");
            await recordStep("sign", res.success ? "done" : "failed", cmdStr, res.exit_code, res.stdout, res.stderr);
            if (res.success) setSignedBomPath(xmlBomPath);
            dispatch({ type: "NEXT" });
        } catch { /* logged */ }
    }, [xmlBomPath, keyFile, runSidecarCmd, recordStep]);

    const handleVerify = useCallback(async () => {
        // Use public key — derive path from private key or ask user
        const pubKey = keyFile.replace("private", "public");
        const cmdStr = `cyclonedx verify all --bom-file ${signedBomPath} --key-file ${pubKey}`;
        await recordStep("verify", "running", cmdStr, null, null, null);
        try {
            const res = await runSidecarCmd("cyclonedx", [
                "verify", "all",
                "--bom-file", signedBomPath,
                "--key-file", pubKey,
            ], "XML DSig Verify");
            await recordStep("verify", res.success ? "done" : "failed", cmdStr, res.exit_code, res.stdout, res.stderr);
            dispatch({ type: "NEXT" });
        } catch { /* logged */ }
    }, [signedBomPath, keyFile, runSidecarCmd, recordStep]);

    const handleExport = useCallback(async () => {
        const csvPath = await save({
            defaultPath: `${outputDir || projectDir}/nist_ssdf-report.csv`,
            filters: [{ name: "CSV", extensions: ["csv"] }],
        });
        if (csvPath) {
            const cmdStr = `sbom-checker-go csv --include-hashes --include-gost ${fixedBomPath} ${csvPath}`;
            await recordStep("export", "running", cmdStr, null, null, null);
            try {
                const res = await runSidecarCmd("sbom-checker-go", [
                    "csv",
                    "--include-hashes",
                    "--include-gost",
                    fixedBomPath,
                    csvPath as string,
                ], "CSV export");
                await recordStep("export", res.success ? "done" : "failed", cmdStr, res.exit_code, res.stdout, res.stderr);
                if (res.success) await recordArtifact(csvPath as string, "csv-report");
                dispatch({ type: "NEXT" });
            } catch { /* logged */ }
        }
    }, [fixedBomPath, outputDir, projectDir, runSidecarCmd, recordStep, recordArtifact]);

    const reset = () => {
        dispatch({ type: "RESET" });
        setProjectDir("");
        setOutputDir("");
        setBomPath("");
        setFixedBomPath("");
        setXmlBomPath("");
        setSignedBomPath("");
        setKeyFile("");
        setLogs([]);
        setRunId(null);
        runIdRef.current = null;
    };

    const stepIndex = STEPS_META.findIndex((s) => s.id === step);

    // ─── Render ─────────────────────────────────────

    return (
        <div className="nist_ssdf-panel">
            {/* Progress bar */}
            <div className="nist_ssdf-progress">
                {STEPS_META.map((s, i) => {
                    const isDone = i < stepIndex || step === "done";
                    const isCurrent = s.id === step;
                    return (
                        <div key={s.id} className={`nist_ssdf-step ${isDone ? "done" : ""} ${isCurrent ? "current" : ""}`}>
                            <div className="nist_ssdf-step-dot">
                                {isDone ? "✓" : s.icon}
                            </div>
                            <span className="nist_ssdf-step-label">{s.label}</span>
                        </div>
                    );
                })}
                <div className="nist_ssdf-progress-line" style={{ width: `${Math.max(0, (stepIndex / (STEPS_META.length - 1)) * 100)}%` }} />
            </div>

            {/* Step content */}
            <div className="nist_ssdf-content">
                {step === "project" && (
                    <div className="nist_ssdf-step-card fade-in">
                        <h3>1. Выберите проект</h3>
                        <p className="nist_ssdf-hint">Укажите папку проекта для генерации SBOM через cdxgen, или выберите готовый BOM-файл.</p>

                        <div className="nist_ssdf-form-grid">
                            <div className="nist_ssdf-field">
                                <label className="settings-label">Папка проекта</label>
                                <div className="diff-file-btn-row">
                                    <button className="diff-pick-btn" onClick={selectProject}>
                                        📁 {projectDir ? projectDir.split("/").pop() : "Выбрать..."}
                                    </button>
                                </div>
                            </div>
                            <div className="nist_ssdf-field">
                                <label className="settings-label">Папка для результатов (опц.)</label>
                                <div className="diff-file-btn-row">
                                    <button className="diff-pick-btn" onClick={selectOutputDir}>
                                        📁 {outputDir ? outputDir.split("/").pop() : "= папка проекта"}
                                    </button>
                                </div>
                            </div>
                            <div className="nist_ssdf-field">
                                <label className="settings-label">Название приложения</label>
                                <input className="wizard-input" value={appName} onChange={(e) => setAppName(e.target.value)} placeholder="Keycloak" />
                            </div>
                            <div className="nist_ssdf-field">
                                <label className="settings-label">Версия</label>
                                <input className="wizard-input" value={appVersion} onChange={(e) => setAppVersion(e.target.value)} placeholder="26.0.0" />
                            </div>
                            <div className="nist_ssdf-field nist_ssdf-field-wide">
                                <label className="settings-label">Производитель / организация</label>
                                <input className="wizard-input" value={manufacturer} onChange={(e) => setManufacturer(e.target.value)} placeholder="Red Hat / Ваша Компания" />
                            </div>
                        </div>

                        <div className="nist_ssdf-actions">
                            <button className="exec-btn" onClick={() => { if (projectDir) dispatch({ type: "NEXT" }); }} disabled={!projectDir}>
                                Далее → cdxgen
                            </button>
                            <span className="nist_ssdf-or">или</span>
                            <button className="preset-btn" onClick={async () => { await selectExistingBom(); dispatch({ type: "SKIP_TO", step: "validate" }); }}>
                                📂 Загрузить готовый BOM → сразу валидировать
                            </button>
                        </div>
                    </div>
                )}

                {step === "generate" && (
                    <div className="nist_ssdf-step-card fade-in">
                        <h3>2. Генерация SBOM (cdxgen)</h3>
                        <p className="nist_ssdf-hint">Запускаем <code>npx @cyclonedx/cdxgen</code> для сканирования проекта <strong>{projectDir.split("/").pop()}</strong></p>
                        <div className="nist_ssdf-actions">
                            <button className="exec-btn" onClick={handleGenerate} disabled={isRunning}>
                                {isRunning ? <><span className="spinner" /> Генерирую...</> : "🔧 Запустить cdxgen"}
                            </button>
                            <button className="preset-btn" onClick={() => dispatch({ type: "NEXT" })} disabled={isRunning}>
                                Пропустить →
                            </button>
                        </div>
                    </div>
                )}

                {step === "validate" && (
                    <div className="nist_ssdf-step-card fade-in">
                        <h3>3. Валидация CycloneDX</h3>
                        <p className="nist_ssdf-hint">Проверяем структуру BOM через <code>cyclonedx validate --fail-on-errors</code></p>
                        <div className="nist_ssdf-bom-path">📄 {bomPath.split("/").pop()}</div>
                        <div className="nist_ssdf-actions">
                            <button className="exec-btn" onClick={handleValidate} disabled={isRunning || !bomPath}>
                                {isRunning ? <><span className="spinner" /> Валидирую...</> : "✓ Валидировать"}
                            </button>
                        </div>
                    </div>
                )}

                {step === "update" && (
                    <div className="nist_ssdf-step-card fade-in">
                        <h3>4. NIST-фикс (Стрибог + ГОСТ)</h3>
                        <p className="nist_ssdf-hint">
                            <code>sbom-checker-go update</code> добавляет: хэши Стрибог-256,
                            поля attack_surface, security_function, ГОСТ-метаданные
                        </p>
                        <div className="nist_ssdf-bom-path">📄 {bomPath.split("/").pop()} → bom-nist_ssdf-fixed.json</div>
                        <div className="nist_ssdf-actions">
                            <button className="exec-btn" onClick={handleUpdate} disabled={isRunning}>
                                {isRunning ? <><span className="spinner" /> Обновляю...</> : "🏛️ Применить NIST-фикс"}
                            </button>
                        </div>
                    </div>
                )}

                {step === "check" && (
                    <div className="nist_ssdf-step-card fade-in">
                        <h3>5. Финальная NIST-проверка</h3>
                        <p className="nist_ssdf-hint">
                            <code>sbom-checker-go check</code> — валидация хэшей, проверка VCS-источников, полнота ГОСТ-полей
                        </p>
                        <div className="nist_ssdf-bom-path">📄 {fixedBomPath.split("/").pop()}</div>
                        <div className="nist_ssdf-actions">
                            <button className="exec-btn" onClick={handleCheck} disabled={isRunning}>
                                {isRunning ? <><span className="spinner" /> Проверяю...</> : "🛡️ Проверить"}
                            </button>
                        </div>
                    </div>
                )}

                {step === "convert-xml" && (
                    <div className="nist_ssdf-step-card fade-in">
                        <h3>6. Конвертация JSON → XML</h3>
                        <p className="nist_ssdf-hint">
                            XML-формат необходим для вложенной цифровой подписи (XML DSig Enveloped Signature)
                        </p>
                        <div className="nist_ssdf-bom-path">📄 {fixedBomPath.split("/").pop()} → .xml</div>
                        <div className="nist_ssdf-actions">
                            <button className="exec-btn" onClick={handleConvertXml} disabled={isRunning}>
                                {isRunning ? <><span className="spinner" /> Конвертирую...</> : "🔄 Конвертировать в XML"}
                            </button>
                            <button className="preset-btn" onClick={() => dispatch({ type: "SKIP_TO", step: "export" })} disabled={isRunning}>
                                Пропустить подпись →
                            </button>
                        </div>
                    </div>
                )}

                {step === "sign" && (
                    <div className="nist_ssdf-step-card fade-in">
                        <h3>7. Подпись BOM (XML DSig RSA)</h3>
                        <p className="nist_ssdf-hint">
                            Вложенная подпись XML DSig с RSA 2048-bit ключом. NIST требует цифровую подпись SBOM.
                        </p>
                        <div className="nist_ssdf-bom-path">📄 {xmlBomPath.split("/").pop()}</div>
                        <div className="nist_ssdf-form-grid">
                            <div className="nist_ssdf-field">
                                <label className="settings-label">Приватный ключ RSA (.pem)</label>
                                <div className="diff-file-btn-row">
                                    <button className="diff-pick-btn" onClick={selectKeyFile}>
                                        🔑 {keyFile ? keyFile.split("/").pop() : "Выбрать..."}
                                    </button>
                                </div>
                            </div>
                        </div>
                        <div className="nist_ssdf-actions">
                            <button className="exec-btn" onClick={handleSign} disabled={isRunning || !keyFile}>
                                {isRunning ? <><span className="spinner" /> Подписываю...</> : "✍️ Подписать BOM"}
                            </button>
                        </div>
                    </div>
                )}

                {step === "verify" && (
                    <div className="nist_ssdf-step-card fade-in">
                        <h3>8. Верификация подписи</h3>
                        <p className="nist_ssdf-hint">
                            Проверяем все XML DSig подписи в документе публичным ключом
                        </p>
                        <div className="nist_ssdf-bom-path">📄 {signedBomPath.split("/").pop()}</div>
                        <div className="nist_ssdf-actions">
                            <button className="exec-btn" onClick={handleVerify} disabled={isRunning || !signedBomPath}>
                                {isRunning ? <><span className="spinner" /> Верифицирую...</> : "✅ Верифицировать"}
                            </button>
                        </div>
                    </div>
                )}

                {step === "export" && (
                    <div className="nist_ssdf-step-card fade-in">
                        <h3>9. Экспорт отчёта</h3>
                        <p className="nist_ssdf-hint">Сохраните CSV-отчёт для предоставления экспертной организации</p>
                        <div className="nist_ssdf-actions">
                            <button className="exec-btn" onClick={handleExport} disabled={isRunning}>
                                {isRunning ? <><span className="spinner" /> Экспортирую...</> : "📊 Сохранить CSV"}
                            </button>
                        </div>
                    </div>
                )}

                {step === "done" && (
                    <div className="nist_ssdf-step-card nist_ssdf-done fade-in">
                        <span className="nist_ssdf-done-icon">✅</span>
                        <h3>Готово!</h3>
                        <p>BOM полностью соответствует требованиям NIST (письмо 240/24)</p>
                        <div className="nist_ssdf-done-files">
                            {fixedBomPath && <div className="nist_ssdf-bom-path">🛡️ {fixedBomPath}</div>}
                        </div>
                        <button className="preset-btn" onClick={reset} style={{ marginTop: 16 }}>
                            🔄 Начать заново
                        </button>
                    </div>
                )}
            </div>

            {/* Log panel */}
            <div className="nist_ssdf-log-panel">
                <div className="nist_ssdf-log-header" onClick={() => setExpandedLog(!expandedLog)}>
                    <span>📋 Лог выполнения ({logs.length})</span>
                    <span>{expandedLog ? "▼" : "▶"}</span>
                </div>
                {expandedLog && (
                    <div className="nist_ssdf-log-scroll">
                        {logs.length === 0 ? (
                            <div className="nist_ssdf-log-empty">Пока пусто — выберите проект для&nbsp;начала</div>
                        ) : (
                            logs.map((log, i) => (
                                <div key={i} className={`nist_ssdf-log-line nist_ssdf-log-${log.type}`}>
                                    {log.text}
                                </div>
                            ))
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
