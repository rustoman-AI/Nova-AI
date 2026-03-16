import { useState, useCallback } from "react";

// ─── Config model ──────────────────────────────────
interface BomConfig {
    schemaVersion: string;
    outputFormat: "json" | "xml" | "both";
    componentName: string;
    componentGroup: string;
    componentVersion: string;
    projectType: string;
    includeBomSerialNumber: boolean;
    includeLicenseText: boolean;
    includeBuildSystem: boolean;
    includeMetadataResolution: boolean;
    includeBuildEnvironment: boolean;
    includeConfigs: string;
    skipConfigs: string;
    organizationName: string;
    organizationUrl: string;
    buildSystemEnvVar: string;
}

const DEFAULTS: BomConfig = {
    schemaVersion: "1.6", outputFormat: "both",
    componentName: "${project.name}", componentGroup: "${project.group}",
    componentVersion: "${project.version}", projectType: "library",
    includeBomSerialNumber: true, includeLicenseText: false,
    includeBuildSystem: true, includeMetadataResolution: true,
    includeBuildEnvironment: false, includeConfigs: "",
    skipConfigs: "", organizationName: "", organizationUrl: "",
    buildSystemEnvVar: "",
};

const SCHEMA_VERSIONS = ["1.6", "1.5", "1.4", "1.3", "1.2", "1.1", "1.0"];
const PROJECT_TYPES = ["library", "framework", "application", "container", "platform", "device", "device-driver", "firmware", "file", "machine-learning-model", "data"];

function generateGradleKts(cfg: BomConfig): string {
    let s = `plugins {\n    id("org.cyclonedx.bom") version "3.2.0"\n}\n\ncyclonedxBom {\n`;
    s += `    schemaVersion = "${cfg.schemaVersion}"\n`;
    s += `    componentName = "${cfg.componentName}"\n`;
    s += `    componentGroup = "${cfg.componentGroup}"\n`;
    s += `    componentVersion = "${cfg.componentVersion}"\n`;
    s += `    projectType = "${cfg.projectType}"\n`;
    s += `    includeBomSerialNumber = ${cfg.includeBomSerialNumber}\n`;
    s += `    includeLicenseText = ${cfg.includeLicenseText}\n`;
    s += `    includeBuildSystem = ${cfg.includeBuildSystem}\n`;
    s += `    includeMetadataResolution = ${cfg.includeMetadataResolution}\n`;
    s += `    includeBuildEnvironment = ${cfg.includeBuildEnvironment}\n`;
    if (cfg.includeConfigs) s += `    includeConfigs = listOf(${cfg.includeConfigs.split(",").map(c => `"${c.trim()}"`).join(", ")})\n`;
    if (cfg.skipConfigs) s += `    skipConfigs = listOf(${cfg.skipConfigs.split(",").map(c => `"${c.trim()}"`).join(", ")})\n`;
    if (cfg.buildSystemEnvVar) s += `    buildSystemEnvironmentVariable = '${cfg.buildSystemEnvVar}'\n`;
    if (cfg.organizationName) {
        s += `    organizationalEntity {\n        name = "${cfg.organizationName}"\n`;
        if (cfg.organizationUrl) s += `        urls = listOf("${cfg.organizationUrl}")\n`;
        s += `    }\n`;
    }
    if (cfg.outputFormat === "json") s += `    xmlOutput.unsetConvention()\n`;
    else if (cfg.outputFormat === "xml") s += `    jsonOutput.unsetConvention()\n`;
    s += `}\n`;
    return s;
}

function generateGradleGroovy(cfg: BomConfig): string {
    let s = `plugins {\n    id 'org.cyclonedx.bom' version '3.2.0'\n}\n\ncyclonedxBom {\n`;
    s += `    schemaVersion = '${cfg.schemaVersion}'\n`;
    s += `    componentName = '${cfg.componentName}'\n`;
    s += `    componentGroup = '${cfg.componentGroup}'\n`;
    s += `    componentVersion = '${cfg.componentVersion}'\n`;
    s += `    projectType = '${cfg.projectType}'\n`;
    s += `    includeBomSerialNumber = ${cfg.includeBomSerialNumber}\n`;
    s += `    includeLicenseText = ${cfg.includeLicenseText}\n`;
    s += `    includeBuildSystem = ${cfg.includeBuildSystem}\n`;
    s += `    includeMetadataResolution = ${cfg.includeMetadataResolution}\n`;
    s += `    includeBuildEnvironment = ${cfg.includeBuildEnvironment}\n`;
    if (cfg.includeConfigs) s += `    includeConfigs = [${cfg.includeConfigs.split(",").map(c => `'${c.trim()}'`).join(", ")}]\n`;
    if (cfg.skipConfigs) s += `    skipConfigs = [${cfg.skipConfigs.split(",").map(c => `'${c.trim()}'`).join(", ")}]\n`;
    if (cfg.buildSystemEnvVar) s += `    buildSystemEnvironmentVariable = '${cfg.buildSystemEnvVar}'\n`;
    if (cfg.organizationName) {
        s += `    organizationalEntity {\n        name = '${cfg.organizationName}'\n`;
        if (cfg.organizationUrl) s += `        urls = ['${cfg.organizationUrl}']\n`;
        s += `    }\n`;
    }
    if (cfg.outputFormat === "json") s += `    xmlOutput.unsetConvention()\n`;
    else if (cfg.outputFormat === "xml") s += `    jsonOutput.unsetConvention()\n`;
    s += `}\n`;
    return s;
}

// ─── Main Component ────────────────────────────────
export default function BomGeneratorWizard() {
    const [cfg, setCfg] = useState<BomConfig>({ ...DEFAULTS });
    const [lang, setLang] = useState<"kts" | "groovy">("kts");
    const [copied, setCopied] = useState(false);

    const update = useCallback(<K extends keyof BomConfig>(key: K, val: BomConfig[K]) => {
        setCfg(prev => ({ ...prev, [key]: val }));
    }, []);

    const output = lang === "kts" ? generateGradleKts(cfg) : generateGradleGroovy(cfg);

    const copyToClipboard = useCallback(() => {
        navigator.clipboard.writeText(output);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
    }, [output]);

    return (
        <div className="genwiz-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">BOM Generator Wizard</h2>
                <div className="genwiz-lang-toggle">
                    <button className={`genwiz-lang-btn ${lang === "kts" ? "genwiz-lang-active" : ""}`} onClick={() => setLang("kts")}>Kotlin DSL</button>
                    <button className={`genwiz-lang-btn ${lang === "groovy" ? "genwiz-lang-active" : ""}`} onClick={() => setLang("groovy")}>Groovy</button>
                </div>
            </div>

            <div className="genwiz-content">
                <div className="genwiz-form">
                    {/* Core */}
                    <div className="genwiz-section"><h4>📦 Core</h4>
                        <div className="genwiz-row">
                            <label>Schema Version</label>
                            <select value={cfg.schemaVersion} onChange={e => update("schemaVersion", e.target.value)}>
                                {SCHEMA_VERSIONS.map(v => <option key={v}>{v}</option>)}
                            </select>
                        </div>
                        <div className="genwiz-row">
                            <label>Output Format</label>
                            <select value={cfg.outputFormat} onChange={e => update("outputFormat", e.target.value as any)}>
                                <option value="both">JSON + XML</option>
                                <option value="json">JSON only</option>
                                <option value="xml">XML only</option>
                            </select>
                        </div>
                        <div className="genwiz-row">
                            <label>Project Type</label>
                            <select value={cfg.projectType} onChange={e => update("projectType", e.target.value)}>
                                {PROJECT_TYPES.map(t => <option key={t}>{t}</option>)}
                            </select>
                        </div>
                    </div>

                    {/* Component */}
                    <div className="genwiz-section"><h4>🏷️ Component</h4>
                        <div className="genwiz-row"><label>Name</label><input value={cfg.componentName} onChange={e => update("componentName", e.target.value)} /></div>
                        <div className="genwiz-row"><label>Group</label><input value={cfg.componentGroup} onChange={e => update("componentGroup", e.target.value)} /></div>
                        <div className="genwiz-row"><label>Version</label><input value={cfg.componentVersion} onChange={e => update("componentVersion", e.target.value)} /></div>
                    </div>

                    {/* Toggles */}
                    <div className="genwiz-section"><h4>⚙️ Options</h4>
                        {([
                            ["includeBomSerialNumber", "BOM Serial Number"],
                            ["includeLicenseText", "License Text"],
                            ["includeBuildSystem", "Build System Info"],
                            ["includeMetadataResolution", "Metadata Resolution"],
                            ["includeBuildEnvironment", "Build Environment"],
                        ] as [keyof BomConfig, string][]).map(([key, label]) => (
                            <div key={key} className="genwiz-toggle">
                                <input type="checkbox" checked={cfg[key] as boolean} onChange={e => update(key, e.target.checked as any)} id={`genwiz-${key}`} />
                                <label htmlFor={`genwiz-${key}`}>{label}</label>
                            </div>
                        ))}
                    </div>

                    {/* Filtering */}
                    <div className="genwiz-section"><h4>🔍 Config Filtering</h4>
                        <div className="genwiz-row"><label>Include (regex, comma-sep)</label><input placeholder="runtimeClasspath, compileClasspath" value={cfg.includeConfigs} onChange={e => update("includeConfigs", e.target.value)} /></div>
                        <div className="genwiz-row"><label>Skip (regex, comma-sep)</label><input placeholder="testRuntimeClasspath" value={cfg.skipConfigs} onChange={e => update("skipConfigs", e.target.value)} /></div>
                    </div>

                    {/* Organization */}
                    <div className="genwiz-section"><h4>🏢 Organization</h4>
                        <div className="genwiz-row"><label>Name</label><input value={cfg.organizationName} onChange={e => update("organizationName", e.target.value)} /></div>
                        <div className="genwiz-row"><label>URL</label><input value={cfg.organizationUrl} onChange={e => update("organizationUrl", e.target.value)} /></div>
                        <div className="genwiz-row"><label>Build System Env Var</label><input placeholder="BUILD_URL or ${SERVER}/jobs/${JOB_ID}" value={cfg.buildSystemEnvVar} onChange={e => update("buildSystemEnvVar", e.target.value)} /></div>
                    </div>
                </div>

                {/* Preview */}
                <div className="genwiz-preview">
                    <div className="genwiz-preview-header">
                        <span>📄 build.gradle{lang === "kts" ? ".kts" : ""}</span>
                        <button className="exec-btn" onClick={copyToClipboard}>{copied ? "✅ Copied!" : "📋 Copy"}</button>
                    </div>
                    <pre className="genwiz-code"><code>{output}</code></pre>
                </div>
            </div>
        </div>
    );
}
