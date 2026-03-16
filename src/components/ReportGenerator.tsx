import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";

// ─── Report Templates ──────────────────────────────
const TEMPLATES = [
    { id: "nist_ssdf", label: "NIST Compliance", icon: "🏛️", desc: "Полный отчёт для сертификации: метаданные, компоненты, лицензии, уязвимости, крипто" },
    { id: "ntia", label: "NTIA Minimum Elements", icon: "🇺🇸", desc: "NTIA Software Transparency: supplier, name, version, identifiers, deps, author, timestamp" },
    { id: "license", label: "License Audit", icon: "🏷️", desc: "Licensing analysis: copyleft detection, compatibility matrix, risk assessment" },
    { id: "security", label: "Security Posture", icon: "🛡️", desc: "Vulnerability summary, VEX analysis, crypto readiness, dependency health" },
] as const;

type TemplateId = typeof TEMPLATES[number]["id"];

function generateReport(bom: any, template: TemplateId): string {
    const meta = bom.metadata || {};
    const components: any[] = bom.components || [];
    const vulns: any[] = bom.vulnerabilities || [];
    const deps: any[] = bom.dependencies || [];
    const now = new Date().toISOString().slice(0, 19);

    const css = `body{font-family:Inter,system-ui,sans-serif;margin:40px;color:#1e293b;line-height:1.5;max-width:900px}
h1{font-size:1.6rem;border-bottom:2px solid #6366f1;padding-bottom:8px}
h2{font-size:1.2rem;color:#6366f1;margin-top:28px}
h3{font-size:1rem;color:#334155}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:0.85rem}
th{background:#f1f5f9;padding:6px 10px;text-align:left;border:1px solid #e2e8f0;font-weight:600}
td{padding:5px 10px;border:1px solid #e2e8f0}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:0.75rem;font-weight:600}
.ok{background:#dcfce7;color:#16a34a}.warn{background:#fef3c7;color:#d97706}.fail{background:#fee2e2;color:#dc2626}
.stat{display:inline-block;padding:4px 12px;border-radius:8px;background:#f1f5f9;margin:3px;font-weight:600}
.footer{margin-top:40px;padding-top:12px;border-top:1px solid #e2e8f0;font-size:0.75rem;color:#94a3b8}
@media print{body{margin:20px}h1,h2{page-break-after:avoid}table{page-break-inside:avoid}}`;

    let html = `<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><title>${template.toUpperCase()} Report</title><style>${css}</style></head><body>`;

    // Header
    html += `<h1>📋 ${template === "nist_ssdf" ? "NIST Compliance" : template === "ntia" ? "NTIA Minimum Elements" : template === "license" ? "License Audit" : "Security Posture"} Report</h1>`;
    html += `<p>Generated: ${now}</p>`;

    // Metadata
    html += `<h2>📦 BOM Metadata</h2>`;
    html += `<table><tr><th>Field</th><th>Value</th></tr>`;
    html += `<tr><td>Format</td><td>${bom.bomFormat || "—"}</td></tr>`;
    html += `<tr><td>Spec Version</td><td>${bom.specVersion || "—"}</td></tr>`;
    html += `<tr><td>Serial Number</td><td>${bom.serialNumber || "—"}</td></tr>`;
    html += `<tr><td>Timestamp</td><td>${meta.timestamp || "—"}</td></tr>`;
    html += `<tr><td>Component</td><td>${meta.component?.name || "—"} ${meta.component?.version || ""}</td></tr>`;
    html += `<tr><td>Total Components</td><td>${components.length}</td></tr>`;
    html += `<tr><td>Dependencies</td><td>${deps.length}</td></tr>`;
    html += `<tr><td>Vulnerabilities</td><td>${vulns.length}</td></tr>`;
    html += `</table>`;

    // Template-specific sections
    if (template === "nist_ssdf" || template === "license") {
        html += `<h2>🏷️ License Analysis</h2>`;
        const licMap = new Map<string, number>();
        for (const c of components) {
            const lics = c.licenses?.map((l: any) => l.license?.id || l.expression || "unknown") || ["(none)"];
            for (const lid of lics) licMap.set(lid, (licMap.get(lid) || 0) + 1);
        }
        html += `<table><tr><th>License</th><th>Count</th></tr>`;
        for (const [lid, cnt] of [...licMap].sort((a, b) => b[1] - a[1])) {
            html += `<tr><td>${lid}</td><td>${cnt}</td></tr>`;
        }
        html += `</table>`;
    }

    if (template === "nist_ssdf" || template === "security") {
        html += `<h2>🛡️ Vulnerabilities (${vulns.length})</h2>`;
        if (vulns.length > 0) {
            html += `<table><tr><th>ID</th><th>Severity</th><th>CVSS</th><th>Status</th><th>Affects</th></tr>`;
            for (const v of vulns.slice(0, 100)) {
                const sev = v.ratings?.[0]?.severity || "?";
                const score = v.ratings?.[0]?.score?.toFixed(1) || "—";
                const st = v.analysis?.state || "?";
                const affects = (v.affects || []).map((a: any) => a.ref).join(", ");
                html += `<tr><td>${v.id || "?"}</td><td><span class="badge ${sev === "critical" || sev === "high" ? "fail" : sev === "medium" ? "warn" : "ok"}">${sev}</span></td><td>${score}</td><td>${st.replace(/_/g, " ")}</td><td>${affects || "—"}</td></tr>`;
            }
            html += `</table>`;
        } else {
            html += `<p>No vulnerability data in this BOM.</p>`;
        }
    }

    // Component inventory (all templates)
    html += `<h2>📦 Component Inventory (${components.length})</h2>`;
    html += `<table><tr><th>#</th><th>Name</th><th>Version</th><th>Type</th><th>PURL</th><th>Hashes</th></tr>`;
    for (const [i, c] of components.slice(0, 200).entries()) {
        html += `<tr><td>${i + 1}</td><td>${c.name || "?"}</td><td>${c.version || "—"}</td><td>${c.type || "—"}</td><td style="font-size:0.75rem;word-break:break-all">${c.purl || "—"}</td><td>${c.hashes?.length || 0}</td></tr>`;
    }
    if (components.length > 200) html += `<tr><td colspan="6">... and ${components.length - 200} more</td></tr>`;
    html += `</table>`;

    if (template === "ntia") {
        html += `<h2>📋 NTIA Minimum Elements Check</h2>`;
        const checks = [
            { name: "Supplier Name", ok: !!(meta.component?.supplier?.name || meta.component?.author) },
            { name: "Component Name", ok: !!meta.component?.name },
            { name: "Version", ok: !!meta.component?.version },
            { name: "Unique Identifiers", ok: components.some((c: any) => c.purl) },
            { name: "Dependency Relationships", ok: deps.length > 0 },
            { name: "Author", ok: !!(meta.authors?.length || meta.component?.author) },
            { name: "Timestamp", ok: !!meta.timestamp },
        ];
        html += `<table><tr><th>Element</th><th>Status</th></tr>`;
        for (const ch of checks) {
            html += `<tr><td>${ch.name}</td><td><span class="badge ${ch.ok ? "ok" : "fail"}">${ch.ok ? "✅ Present" : "❌ Missing"}</span></td></tr>`;
        }
        html += `</table>`;
        html += `<p><span class="stat">${checks.filter(c => c.ok).length}/${checks.length} elements present</span></p>`;
    }

    html += `<div class="footer">Generated by CycloneDX Tauri UI • ${now}</div>`;
    html += `</body></html>`;
    return html;
}

// ─── Main Component ────────────────────────────────
export default function ReportGenerator() {
    const [selectedTemplate, setSelectedTemplate] = useState<TemplateId>("nist_ssdf");
    const [generating, setGenerating] = useState(false);
    const [result, setResult] = useState<string | null>(null);

    const generate = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select BOM for report",
        });
        if (!f) return;

        setGenerating(true);
        setResult(null);
        try {
            const content = await invoke<string>("read_file_contents", { path: f as string });
            const bom = JSON.parse(content);
            const html = generateReport(bom, selectedTemplate);

            const outPath = await save({
                filters: [{ name: "HTML Report", extensions: ["html"] }],
                defaultPath: `bom-${selectedTemplate}-report.html`,
            });
            if (outPath) {
                await invoke("write_file_contents", { path: outPath, contents: html });
                setResult(`✅ Report saved: ${outPath}`);
            }
        } catch (e: any) {
            setResult(`❌ ${e.message || e}`);
        }
        setGenerating(false);
    }, [selectedTemplate]);

    return (
        <div className="rpt-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">Report Generator</h2>
            </div>

            <div className="rpt-content">
                <div className="rpt-templates">
                    {TEMPLATES.map(t => (
                        <div key={t.id}
                            className={`rpt-template-card ${selectedTemplate === t.id ? "rpt-template-active" : ""}`}
                            onClick={() => setSelectedTemplate(t.id)}
                        >
                            <div className="rpt-template-header">
                                <span className="rpt-template-icon">{t.icon}</span>
                                <span className="rpt-template-label">{t.label}</span>
                            </div>
                            <div className="rpt-template-desc">{t.desc}</div>
                        </div>
                    ))}
                </div>

                <button className="exec-btn" onClick={generate} disabled={generating} style={{ alignSelf: "flex-start" }}>
                    {generating ? "⏳ Generating..." : "📄 Select BOM & Generate Report"}
                </button>

                {result && (
                    <div className={`rpt-result ${result.startsWith("✅") ? "rpt-result-ok" : "rpt-result-err"}`}>
                        {result}
                    </div>
                )}
            </div>
        </div>
    );
}
