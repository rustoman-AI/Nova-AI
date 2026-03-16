import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ComplianceMetrics {
  nist_score: number;
  eu_cra_readiness: number;
  nist_ssdf_level: number;
  slsa_level: number;
}

interface VelocityMetrics {
  average_patch_time_sec: number;
  developer_hours_saved: number;
  mttr_minutes: number;
}

interface ExecutiveReportData {
  overall_security_score: number;
  critical_threats_blocked: number;
  high_vulns_remaining: number;
  ai_patches_applied: number;
  compliance: ComplianceMetrics;
  velocity: VelocityMetrics;
}

export default function ExecutiveReport() {
  const [report, setReport] = useState<ExecutiveReportData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadReport() {
      try {
        const data = await invoke<ExecutiveReportData>("engine_generate_executive_report");
        setReport(data);
      } catch (e) {
        console.error("Failed to load executive report:", e);
      } finally {
        setLoading(false);
      }
    }
    loadReport();
  }, []);

  if (loading) {
    return (
      <div className="rep-loading" style={{ color: "#8c8c8c", padding: "40px", textAlign: "center" }}>
        Aggregating Graph & Swarm Metrics...
      </div>
    );
  }

  if (!report) {
    return (
      <div className="rep-error" style={{ color: "#ff4d4f", padding: "40px", textAlign: "center" }}>
        Failed to fetch the Executive Report. Ensure the swarm engine is running.
      </div>
    );
  }

  const getScoreColor = (score: number) => {
    if (score >= 90) return "#52c41a"; // green
    if (score >= 75) return "#faad14"; // yellow
    return "#ff4d4f"; // red
  };

  return (
    <div className="exec-report-container">
      <div className="er-header">
        <div className="er-title">
          <h2>📊 Executive Boardroom Summary</h2>
          <p>Continuous Compliance & DevSecOps ROI Dashboard</p>
        </div>
        <button className="er-export-btn">⬇ Export PDF</button>
      </div>

      <div className="er-main-grid">
        {/* Top KPIs */}
        <div className="er-kpi-row">
          <div className="er-kpi-card highlight">
            <div className="er-kpi-label">Overall Security Posture</div>
            <div className="er-kpi-val" style={{ color: getScoreColor(report.overall_security_score) }}>
              {report.overall_security_score.toFixed(1)}/100
            </div>
            <div className="er-kpi-sub">Graph Health Index</div>
          </div>
          <div className="er-kpi-card">
            <div className="er-kpi-label">Critical Threats Blocked</div>
            <div className="er-kpi-val" style={{ color: "#52c41a" }}>{report.critical_threats_blocked}</div>
            <div className="er-kpi-sub">Swarm E-STOPs & Sandboxing</div>
          </div>
          <div className="er-kpi-card">
            <div className="er-kpi-label">AI Patches Applied</div>
            <div className="er-kpi-val" style={{ color: "#1890ff" }}>{report.ai_patches_applied}</div>
            <div className="er-kpi-sub">Autonomous Auto-Remediation</div>
          </div>
          <div className="er-kpi-card">
            <div className="er-kpi-label">High Vulns Remaining</div>
            <div className="er-kpi-val" style={{ color: report.high_vulns_remaining > 50 ? "#ff4d4f" : "#faad14" }}>
              {report.high_vulns_remaining}
            </div>
            <div className="er-kpi-sub">Awaiting Human Review</div>
          </div>
        </div>

        {/* Two Column Layout */}
        <div className="er-columns">
          {/* Compliance Section */}
          <div className="er-column">
            <h3>🛡️ Regulatory Readiness</h3>
            <div className="er-panel">
              <div className="er-metric-row">
                <span className="er-metric-name">EU Cyber Resilience Act (CRA)</span>
                <div className="er-bar-container">
                  <div className="er-bar-fill" style={{ width: `${report.compliance.eu_cra_readiness}%`, background: getScoreColor(report.compliance.eu_cra_readiness) }}></div>
                </div>
                <span className="er-metric-num">{report.compliance.eu_cra_readiness}%</span>
              </div>
              <div className="er-metric-row">
                <span className="er-metric-name">NIST SSDF Score</span>
                <div className="er-bar-container">
                  <div className="er-bar-fill" style={{ width: `${report.compliance.nist_score}%`, background: getScoreColor(report.compliance.nist_score) }}></div>
                </div>
                <span className="er-metric-num">{report.compliance.nist_score}%</span>
              </div>
              <div className="er-metric-row">
                <span className="er-metric-name">SLSA Attestation Level</span>
                <span className="er-badge slsa">Level {report.compliance.slsa_level}</span>
              </div>
              <div className="er-metric-row">
                <span className="er-metric-name">NIST Trust Standard</span>
                <span className="er-badge nist_ssdf">Level {report.compliance.nist_ssdf_level}</span>
              </div>
            </div>
          </div>

          {/* DevOps Velocity ROI */}
          <div className="er-column">
            <h3>💨 Swarm Developer ROI</h3>
            <div className="er-panel">
              <div className="er-roi-box">
                <div className="er-roi-icon">⏱️</div>
                <div className="er-roi-info">
                  <div className="er-roi-val">{report.velocity.average_patch_time_sec}s</div>
                  <div className="er-roi-label">Avg Auto-Patch Time</div>
                </div>
              </div>
              <div className="er-roi-box highlight-roi">
                <div className="er-roi-icon">💰</div>
                <div className="er-roi-info">
                  <div className="er-roi-val">{report.velocity.developer_hours_saved.toFixed(1)} hrs</div>
                  <div className="er-roi-label">Total Engineering Time Saved by Swarm</div>
                </div>
              </div>
              <div className="er-roi-box">
                <div className="er-roi-icon">📉</div>
                <div className="er-roi-info">
                  <div className="er-roi-val">{report.velocity.mttr_minutes.toFixed(1)} mins</div>
                  <div className="er-roi-label">Mean Time To Recovery (MTTR)</div>
                </div>
              </div>
            </div>
          </div>
        </div>

      </div>

      <style>{`
        .exec-report-container {
          padding: 30px 40px;
          height: 100%;
          overflow-y: auto;
          background: #0d1117;
          color: #c9d1d9;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }

        .er-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-end;
          margin-bottom: 30px;
          border-bottom: 1px solid #30363d;
          padding-bottom: 20px;
        }

        .er-title h2 {
          margin: 0 0 8px 0;
          font-size: 2rem;
          background: -webkit-linear-gradient(#4facfe, #00f2fe);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }

        .er-title p {
          margin: 0;
          color: #8b949e;
          font-size: 1.1rem;
        }

        .er-export-btn {
          background: #238636;
          color: #ffffff;
          border: 1px solid rgba(240, 246, 252, 0.1);
          padding: 8px 16px;
          border-radius: 6px;
          font-weight: 600;
          cursor: pointer;
          transition: 0.2s background;
        }

        .er-export-btn:hover { background: #2ea043; }

        .er-main-grid {
          display: flex;
          flex-direction: column;
          gap: 30px;
        }

        .er-kpi-row {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 20px;
        }

        .er-kpi-card {
          background: #161b22;
          border: 1px solid #30363d;
          border-radius: 12px;
          padding: 24px 20px;
          text-align: center;
          transition: transform 0.2s;
        }

        .er-kpi-card:hover { transform: translateY(-3px); border-color: #8b949e; }

        .er-kpi-card.highlight {
          background: linear-gradient(180deg, rgba(88,166,255,0.05) 0%, #161b22 100%);
          border-top: 3px solid #58a6ff;
        }

        .er-kpi-label {
          font-size: 0.85rem;
          text-transform: uppercase;
          letter-spacing: 1px;
          color: #8b949e;
          margin-bottom: 10px;
        }

        .er-kpi-val {
          font-size: 3rem;
          font-weight: 700;
          line-height: 1.2;
          margin-bottom: 8px;
        }

        .er-kpi-sub {
          font-size: 0.9rem;
          color: #6e7681;
        }

        .er-columns {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 20px;
        }

        .er-column h3 {
          margin: 0 0 16px 0;
          font-size: 1.2rem;
          color: #e6edf3;
        }

        .er-panel {
          background: #161b22;
          border: 1px solid #30363d;
          border-radius: 12px;
          padding: 24px;
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        .er-metric-row {
          display: flex;
          align-items: center;
          gap: 16px;
        }

        .er-metric-name {
          flex: 0 0 160px;
          font-size: 0.95rem;
          font-weight: 500;
        }

        .er-bar-container {
          flex: 1;
          height: 10px;
          background: #010409;
          border-radius: 5px;
          overflow: hidden;
        }

        .er-bar-fill {
          height: 100%;
          border-radius: 5px;
          transition: width 1s ease-out;
        }

        .er-metric-num {
          font-family: monospace;
          font-size: 1.1rem;
          font-weight: bold;
          width: 50px;
          text-align: right;
        }

        .er-badge {
          padding: 4px 12px;
          border-radius: 20px;
          font-size: 0.85rem;
          font-weight: 600;
        }

        .er-badge.slsa { background: rgba(210, 168, 255, 0.15); color: #d2a8ff; border: 1px solid rgba(210, 168, 255, 0.3); }
        .er-badge.nist_ssdf { background: rgba(255, 123, 114, 0.15); color: #ff7b72; border: 1px solid rgba(255, 123, 114, 0.3); }

        .er-roi-box {
          display: flex;
          align-items: center;
          gap: 20px;
          padding: 16px;
          background: #010409;
          border: 1px solid #30363d;
          border-radius: 8px;
        }
        
        .er-roi-box.highlight-roi {
          background: rgba(82, 196, 26, 0.05);
          border-color: rgba(82, 196, 26, 0.3);
        }

        .er-roi-icon {
          font-size: 2.5rem;
        }

        .er-roi-info {
          display: flex;
          flex-direction: column;
        }

        .er-roi-val {
          font-size: 1.8rem;
          font-weight: 700;
          color: #e6edf3;
        }

        .er-roi-label {
          font-size: 0.9rem;
          color: #8b949e;
        }
      `}</style>
    </div>
  );
}
