import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ToolPaths {
    cyclonedx: string;
    cdxgen: string;
    sbomChecker: string;
    trivy: string;
}

interface ProxySettings {
    httpsProxy: string;
    httpProxy: string;
    noProxy: string;
}

interface SslSettings {
    trustAll: boolean;
    caCertPath: string;
}

interface Settings {
    toolPaths: ToolPaths;
    defaultOutputFormat: "json" | "xml" | "csv";
    theme: "dark" | "light";
    airGapMode: boolean;
    proxy: ProxySettings;
    ssl: SslSettings;
}

interface ToolStatus {
    available: boolean;
    version: string;
    path: string;
}

const DEFAULTS: Settings = {
    toolPaths: {
        cyclonedx: "(sidecar)",
        cdxgen: "cdxgen",
        sbomChecker: "sbom-checker-go",
        trivy: "trivy",
    },
    defaultOutputFormat: "json",
    theme: "dark",
    airGapMode: false,
    proxy: { httpsProxy: "", httpProxy: "", noProxy: "localhost,127.0.0.1" },
    ssl: { trustAll: false, caCertPath: "" },
};

function loadSettings(): Settings {
    try {
        const raw = localStorage.getItem("cyclonedx-ui-settings");
        if (raw) return { ...DEFAULTS, ...JSON.parse(raw) };
    } catch { }
    return DEFAULTS;
}

function saveSettings(s: Settings) {
    localStorage.setItem("cyclonedx-ui-settings", JSON.stringify(s));
}

interface SettingsPanelProps {
    open: boolean;
    onClose: () => void;
}

export default function SettingsPanel({ open, onClose }: SettingsPanelProps) {
    const [settings, setSettings] = useState<Settings>(loadSettings);
    const [saved, setSaved] = useState(false);
    const [toolStatuses, setToolStatuses] = useState<Record<string, ToolStatus>>({});
    const [checking, setChecking] = useState(false);

    useEffect(() => {
        if (open) setSettings(loadSettings());
    }, [open]);

    const update = useCallback(
        <K extends keyof Settings>(key: K, value: Settings[K]) => {
            setSettings((prev) => ({ ...prev, [key]: value }));
            setSaved(false);
        },
        []
    );

    const updateToolPath = useCallback(
        (tool: keyof ToolPaths, value: string) => {
            setSettings((prev) => ({
                ...prev,
                toolPaths: { ...prev.toolPaths, [tool]: value },
            }));
            setSaved(false);
        },
        []
    );

    const updateProxy = useCallback(
        (field: keyof ProxySettings, value: string) => {
            setSettings((prev) => ({
                ...prev,
                proxy: { ...prev.proxy, [field]: value },
            }));
            setSaved(false);
        },
        []
    );

    const updateSsl = useCallback(
        <K extends keyof SslSettings>(field: K, value: SslSettings[K]) => {
            setSettings((prev) => ({
                ...prev,
                ssl: { ...prev.ssl, [field]: value },
            }));
            setSaved(false);
        },
        []
    );

    const handleSave = async () => {
        saveSettings(settings);
        // Also save to Rust backend config
        try {
            await invoke("save_config", {
                config: {
                    tool_paths: {
                        cyclonedx: settings.toolPaths.cyclonedx,
                        cdxgen: settings.toolPaths.cdxgen,
                        sbom_checker: settings.toolPaths.sbomChecker,
                        trivy: settings.toolPaths.trivy,
                    },
                    air_gap_mode: settings.airGapMode,
                    proxy: {
                        https_proxy: settings.proxy.httpsProxy,
                        http_proxy: settings.proxy.httpProxy,
                        no_proxy: settings.proxy.noProxy,
                    },
                    ssl: {
                        trust_all: settings.ssl.trustAll,
                        ca_cert_path: settings.ssl.caCertPath,
                    },
                    default_output_format: settings.defaultOutputFormat,
                },
            });
        } catch {
            // localStorage already saved, backend config optional
        }
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
    };

    const handleReset = () => {
        setSettings(DEFAULTS);
        saveSettings(DEFAULTS);
        setSaved(true);
    };

    const handleCheckTools = async () => {
        setChecking(true);
        try {
            const statuses = await invoke<Record<string, ToolStatus>>("check_tool_versions");
            setToolStatuses(statuses);
        } catch {
            setToolStatuses({});
        }
        setChecking(false);
    };

    if (!open) return null;

    return (
        <>
            <div className="drawer-backdrop" onClick={onClose} />
            <div className="settings-modal modal-enter">
                <div className="settings-header">
                    <h3>⚙️ Settings</h3>
                    <button className="drawer-close-btn" onClick={onClose}>×</button>
                </div>

                <div className="settings-body">
                    {/* Air-Gap Mode */}
                    <div className="settings-section">
                        <h4>✈️ Air-Gap Mode</h4>
                        <p className="settings-hint">
                            Enable offline mode — skip auto-downloads, use only pre-installed tools
                        </p>
                        <label className="settings-toggle-row">
                            <input
                                type="checkbox"
                                checked={settings.airGapMode}
                                onChange={(e) => update("airGapMode", e.target.checked)}
                            />
                            <span className="settings-toggle-label">
                                {settings.airGapMode ? "🔴 Air-Gap ON — offline mode" : "🟢 Online — auto-download enabled"}
                            </span>
                        </label>
                    </div>

                    {/* Tool paths */}
                    <div className="settings-section">
                        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                            <h4 style={{ margin: 0 }}>Tool Paths</h4>
                            <button
                                className="settings-check-btn"
                                onClick={handleCheckTools}
                                disabled={checking}
                            >
                                {checking ? "⏳ Checking..." : "🔍 Check Tools"}
                            </button>
                        </div>
                        <p className="settings-hint">
                            Specify full paths or command names (resolved via $PATH).
                            {settings.airGapMode && " In air-gap mode, tools must be pre-installed."}
                        </p>
                        {(Object.entries(settings.toolPaths) as [keyof ToolPaths, string][]).map(
                            ([tool, path]) => {
                                const status = toolStatuses[tool === "sbomChecker" ? "sbom-checker-go" : tool];
                                return (
                                    <div key={tool} className="settings-field">
                                        <label className="settings-label">
                                            {tool}
                                            {status && (
                                                <span className={`settings-tool-status ${status.available ? "ok" : "missing"}`}>
                                                    {status.available ? `✓ ${status.version}` : "✗ not found"}
                                                </span>
                                            )}
                                        </label>
                                        <input
                                            className="wizard-input"
                                            value={path}
                                            onChange={(e) => updateToolPath(tool, e.target.value)}
                                            placeholder={DEFAULTS.toolPaths[tool]}
                                            disabled={tool === "cyclonedx"}
                                        />
                                    </div>
                                );
                            }
                        )}
                    </div>

                    {/* Proxy */}
                    <div className="settings-section">
                        <h4>🌐 Proxy</h4>
                        <p className="settings-hint">
                            Configure proxy for Enterprise environments (applied to env vars on save)
                        </p>
                        <div className="settings-field">
                            <label className="settings-label">HTTPS_PROXY</label>
                            <input
                                className="wizard-input"
                                value={settings.proxy.httpsProxy}
                                onChange={(e) => updateProxy("httpsProxy", e.target.value)}
                                placeholder="https://proxy.corp.com:8443"
                            />
                        </div>
                        <div className="settings-field">
                            <label className="settings-label">HTTP_PROXY</label>
                            <input
                                className="wizard-input"
                                value={settings.proxy.httpProxy}
                                onChange={(e) => updateProxy("httpProxy", e.target.value)}
                                placeholder="http://proxy.corp.com:8080"
                            />
                        </div>
                        <div className="settings-field">
                            <label className="settings-label">NO_PROXY</label>
                            <input
                                className="wizard-input"
                                value={settings.proxy.noProxy}
                                onChange={(e) => updateProxy("noProxy", e.target.value)}
                                placeholder="localhost,127.0.0.1,*.corp.com"
                            />
                        </div>
                    </div>

                    {/* SSL / TLS */}
                    <div className="settings-section">
                        <h4>🔐 SSL / TLS</h4>
                        <p className="settings-hint">
                            Configure certificate trust for internal registries
                        </p>
                        <label className="settings-toggle-row">
                            <input
                                type="checkbox"
                                checked={settings.ssl.trustAll}
                                onChange={(e) => updateSsl("trustAll", e.target.checked)}
                            />
                            <span className="settings-toggle-label">
                                Trust all certificates (insecure — dev/testing only)
                            </span>
                        </label>
                        <div className="settings-field">
                            <label className="settings-label">Custom CA Certificate</label>
                            <input
                                className="wizard-input"
                                value={settings.ssl.caCertPath}
                                onChange={(e) => updateSsl("caCertPath", e.target.value)}
                                placeholder="/etc/ssl/certs/corp-ca.pem"
                            />
                        </div>
                    </div>

                    {/* Output format */}
                    <div className="settings-section">
                        <h4>Default Output Format</h4>
                        <div className="settings-format-btns">
                            {(["json", "xml", "csv"] as const).map((fmt) => (
                                <button
                                    key={fmt}
                                    className={`preset-btn ${settings.defaultOutputFormat === fmt ? "active" : ""}`}
                                    onClick={() => update("defaultOutputFormat", fmt)}
                                >
                                    {fmt.toUpperCase()}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Keyboard shortcuts reference */}
                    <div className="settings-section">
                        <h4>Keyboard Shortcuts</h4>
                        <div className="shortcuts-grid">
                            {[
                                ["Ctrl+Enter", "Execute command"],
                                ["Ctrl+L", "Clear output"],
                                ["Ctrl+K", "Focus command input"],
                                ["Ctrl+O", "Open file picker"],
                                ["Ctrl+1-5", "Switch tabs"],
                                ["↑ / ↓", "Navigate history (in input)"],
                                ["Escape", "Close panels"],
                            ].map(([key, desc]) => (
                                <div key={key} className="shortcut-item">
                                    <kbd className="shortcut-key">{key}</kbd>
                                    <span className="shortcut-desc">{desc}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="settings-footer">
                    <button className="wizard-reset-btn" onClick={handleReset}>
                        Reset to Defaults
                    </button>
                    <button className="exec-btn settings-save-btn" onClick={handleSave}>
                        {saved ? "✓ Saved!" : "Save Settings"}
                    </button>
                </div>

                <style>{`
                    .settings-toggle-row {
                        display: flex;
                        align-items: center;
                        gap: 10px;
                        cursor: pointer;
                        padding: 8px 0;
                    }
                    .settings-toggle-row input[type="checkbox"] {
                        width: 18px;
                        height: 18px;
                        accent-color: #722ed1;
                        cursor: pointer;
                    }
                    .settings-toggle-label {
                        font-size: 13px;
                        color: #b8b8cc;
                    }
                    .settings-check-btn {
                        padding: 4px 12px;
                        border-radius: 6px;
                        border: 1px solid #333;
                        background: transparent;
                        color: #8c8c8c;
                        cursor: pointer;
                        font-size: 12px;
                        transition: all 0.2s;
                    }
                    .settings-check-btn:hover { border-color: #1890ff; color: #1890ff; }
                    .settings-check-btn:disabled { opacity: 0.5; cursor: wait; }
                    .settings-tool-status {
                        font-size: 11px;
                        margin-left: 8px;
                        padding: 2px 8px;
                        border-radius: 10px;
                    }
                    .settings-tool-status.ok {
                        background: #52c41a22;
                        color: #52c41a;
                    }
                    .settings-tool-status.missing {
                        background: #ff4d4f22;
                        color: #ff4d4f;
                    }
                `}</style>
            </div>
        </>
    );
}

export { loadSettings };
export type { Settings };
