import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

interface VulnEntry { id: string; severity: string; score: number; summary: string; affected_package: string; affected_versions: string; fixed_version: string; references: string[]; }
interface LicenseEntry { id: string; name: string; osi_approved: boolean; fsf_free: boolean; category: string; spdx_url: string; }
interface SupplierEntry { name: string; website: string; country: string; trusted: boolean; contact: string; }
interface EnrichmentResult { component_name: string; component_version: string; vulns_found: VulnEntry[]; license_info: LicenseEntry | null; supplier_info: SupplierEntry | null; }
interface EnrichmentReport { total_components: number; enriched_components: number; total_vulns: number; critical_vulns: number; high_vulns: number; components: EnrichmentResult[]; }
interface Stats { vulndb: { packages: number; total_vulns: number }; licensedb: { licenses: number }; supplierdb: { suppliers: number }; }

const SEV_COLOR: Record<string, string> = { CRITICAL: "#ff4d4f", HIGH: "#fa8c16", MEDIUM: "#fadb14", LOW: "#52c41a" };
const CAT_COLOR: Record<string, string> = { permissive: "#52c41a", copyleft: "#fa8c16", "weak-copyleft": "#fadb14", proprietary: "#ff4d4f" };

export default function DataStorePanel() {
    const [stats, setStats] = useState<Stats | null>(null);
    const [report, setReport] = useState<EnrichmentReport | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [filter, setFilter] = useState<"all" | "vulns" | "licenses" | "suppliers">("all");

    useEffect(() => { invoke<Stats>("datastore_stats").then(setStats).catch(() => { }); }, []);

    const handleEnrich = useCallback(async () => {
        try {
            const file = await open({ title: "Select SBOM to enrich", filters: [{ name: "JSON", extensions: ["json"] }] });
            if (!file) return;
            setLoading(true); setError("");
            const result = await invoke<EnrichmentReport>("enrich_sbom", { sbomPath: String(file) });
            setReport(result);
        } catch (e) { setError(String(e)); }
        setLoading(false);
    }, []);

    const filtered = report?.components.filter(c => {
        if (filter === "vulns") return c.vulns_found.length > 0;
        if (filter === "licenses") return c.license_info != null;
        if (filter === "suppliers") return c.supplier_info != null;
        return true;
    }) || [];

    return (
        <div style={{ padding: "24px", maxWidth: 1200, margin: "0 auto" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 24 }}>
                <h2 style={{ margin: 0 }}>🗄️ DataStore Registry</h2>
                <button onClick={handleEnrich} disabled={loading} className="ds-btn ds-btn-primary">
                    {loading ? "⏳ Enriching..." : "🔍 Enrich SBOM"}
                </button>
            </div>

            {/* Stats cards */}
            {stats && (
                <div className="ds-stats-row">
                    <div className="ds-stat-card">
                        <div className="ds-stat-icon">🛡️</div>
                        <div><div className="ds-stat-label">VulnDB</div><div className="ds-stat-value">{stats.vulndb.packages} pkgs / {stats.vulndb.total_vulns} CVEs</div></div>
                    </div>
                    <div className="ds-stat-card">
                        <div className="ds-stat-icon">📜</div>
                        <div><div className="ds-stat-label">LicenseDB</div><div className="ds-stat-value">{stats.licensedb.licenses} SPDX licenses</div></div>
                    </div>
                    <div className="ds-stat-card">
                        <div className="ds-stat-icon">🏢</div>
                        <div><div className="ds-stat-label">SupplierDB</div><div className="ds-stat-value">{stats.supplierdb.suppliers} vendors</div></div>
                    </div>
                </div>
            )}

            {error && <div className="ds-error">{error}</div>}

            {report && (
                <>
                    {/* Summary */}
                    <div className="ds-summary-row">
                        <div className="ds-card"><div className="ds-card-label">Components</div><div className="ds-card-val">{report.total_components}</div></div>
                        <div className="ds-card"><div className="ds-card-label">Enriched</div><div className="ds-card-val" style={{ color: "#722ed1" }}>{report.enriched_components}</div></div>
                        <div className="ds-card" style={{ borderColor: "#ff4d4f" }}><div className="ds-card-label">Vulns</div><div className="ds-card-val" style={{ color: "#ff4d4f" }}>{report.total_vulns}</div></div>
                        <div className="ds-card" style={{ borderColor: "#ff4d4f" }}><div className="ds-card-label">Critical</div><div className="ds-card-val" style={{ color: "#ff4d4f" }}>{report.critical_vulns}</div></div>
                        <div className="ds-card" style={{ borderColor: "#fa8c16" }}><div className="ds-card-label">High</div><div className="ds-card-val" style={{ color: "#fa8c16" }}>{report.high_vulns}</div></div>
                    </div>

                    {/* Filter */}
                    <div className="ds-filter-row">
                        {(["all", "vulns", "licenses", "suppliers"] as const).map(f => (
                            <button key={f} onClick={() => setFilter(f)} className={`ds-filter-btn ${filter === f ? "active" : ""}`}>
                                {f === "all" ? "All" : f === "vulns" ? "🛡️ With Vulns" : f === "licenses" ? "📜 With License" : "🏢 With Supplier"}
                            </button>
                        ))}
                        <span style={{ fontSize: 12, color: "#8c8c8c", marginLeft: 8 }}>{filtered.length} components</span>
                    </div>

                    {/* Results */}
                    <div className="ds-results">
                        {filtered.map((c, i) => (
                            <div key={i} className="ds-comp-card">
                                <div className="ds-comp-header">
                                    <strong>{c.component_name}</strong>
                                    <span className="ds-version">{c.component_version}</span>
                                    {c.vulns_found.length > 0 && <span className="ds-badge ds-badge-red">{c.vulns_found.length} vulns</span>}
                                    {c.license_info && (
                                        <span className="ds-badge" style={{ background: CAT_COLOR[c.license_info.category] + "22", color: CAT_COLOR[c.license_info.category] }}>
                                            {c.license_info.id} ({c.license_info.category})
                                        </span>
                                    )}
                                    {c.supplier_info && (
                                        <span className="ds-badge" style={{ background: c.supplier_info.trusted ? "#52c41a22" : "#ff4d4f22", color: c.supplier_info.trusted ? "#52c41a" : "#ff4d4f" }}>
                                            {c.supplier_info.trusted ? "✓" : "✗"} {c.supplier_info.name} ({c.supplier_info.country})
                                        </span>
                                    )}
                                </div>
                                {c.vulns_found.map(v => (
                                    <div key={v.id} className="ds-vuln-row">
                                        <span className="ds-badge" style={{ background: SEV_COLOR[v.severity] + "22", color: SEV_COLOR[v.severity] }}>
                                            {v.severity} {v.score}
                                        </span>
                                        <code className="ds-vuln-id">{v.id}</code>
                                        <span className="ds-vuln-summary">{v.summary}</span>
                                        <span className="ds-vuln-fix">Fix: {v.fixed_version}</span>
                                    </div>
                                ))}
                            </div>
                        ))}
                    </div>
                </>
            )}

            {!report && !error && (
                <div className="ds-empty">
                    <div style={{ fontSize: 48, marginBottom: 16 }}>🗄️</div>
                    <div style={{ fontSize: 16, marginBottom: 8 }}>DataStore Enrichment</div>
                    <div style={{ color: "#8c8c8c", maxWidth: 420, lineHeight: 1.6 }}>
                        Enrich your SBOM with vulnerability, license, and supplier data from built-in databases. Click "Enrich SBOM" to begin.
                    </div>
                </div>
            )}

            <style>{`
        .ds-btn { padding: 8px 16px; border-radius: 8px; border: 1px solid #333; background: #1a1a2e; color: #e0e0e0; cursor: pointer; font-size: 13px; transition: all 0.2s; }
        .ds-btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
        .ds-btn:disabled { opacity: 0.5; cursor: wait; }
        .ds-btn-primary { border-color: #722ed1; color: #722ed1; }
        .ds-btn-primary:hover { background: #722ed122; }
        .ds-error { padding: 12px; background: #ff4d4f18; border: 1px solid #ff4d4f44; border-radius: 8px; color: #ff7875; margin-bottom: 16px; font-size: 13px; }
        .ds-stats-row { display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
        .ds-stat-card { flex: 1; min-width: 160px; display: flex; align-items: center; gap: 12px; padding: 14px 16px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 12px; }
        .ds-stat-icon { font-size: 24px; }
        .ds-stat-label { font-size: 10px; color: #8c8c8c; text-transform: uppercase; letter-spacing: 1px; }
        .ds-stat-value { font-size: 14px; font-weight: 600; color: #e0e0e0; }
        .ds-summary-row { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
        .ds-card { flex: 1; min-width: 90px; padding: 14px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 12px; text-align: center; }
        .ds-card-label { font-size: 10px; color: #8c8c8c; text-transform: uppercase; letter-spacing: 1px; }
        .ds-card-val { font-size: 26px; font-weight: 700; margin: 2px 0; }
        .ds-filter-row { display: flex; gap: 6px; margin-bottom: 16px; align-items: center; }
        .ds-filter-btn { padding: 6px 14px; border-radius: 20px; border: 1px solid #333; background: transparent; color: #8c8c8c; cursor: pointer; font-size: 12px; transition: all 0.15s; }
        .ds-filter-btn:hover { border-color: #722ed1; color: #e0e0e0; }
        .ds-filter-btn.active { background: #722ed1; border-color: #722ed1; color: #fff; }
        .ds-results { display: grid; gap: 8px; }
        .ds-comp-card { background: #16162a; border: 1px solid #2a2a4a; border-radius: 10px; padding: 12px 16px; }
        .ds-comp-header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .ds-version { font-family: monospace; color: #8c8c8c; font-size: 12px; }
        .ds-badge { padding: 2px 10px; border-radius: 12px; font-size: 10px; white-space: nowrap; }
        .ds-badge-red { background: #ff4d4f22; color: #ff4d4f; }
        .ds-vuln-row { display: flex; align-items: center; gap: 8px; margin-top: 6px; padding: 6px 8px; background: #0e0e1a; border-radius: 6px; font-size: 12px; }
        .ds-vuln-id { color: #b8b8cc; background: #ffffff0a; padding: 1px 6px; border-radius: 4px; }
        .ds-vuln-summary { flex: 1; color: #a0a0b0; }
        .ds-vuln-fix { color: #52c41a; font-family: monospace; font-size: 11px; }
        .ds-empty { text-align: center; padding: 80px 20px; color: #666; }
      `}</style>
        </div>
    );
}
