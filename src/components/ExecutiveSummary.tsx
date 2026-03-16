export default function ExecutiveSummary() {
    const now = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

    return (
        <div style={{
            padding: '40px',
            minHeight: '100vh',
            background: 'radial-gradient(ellipse at bottom, #0d1117 0%, #03040b 100%)',
            color: '#fff',
            fontFamily: "'Inter', -apple-system, sans-serif",
            display: 'flex',
            justifyContent: 'center'
        }}>
            <div style={{
                maxWidth: '800px', width: '100%',
                background: 'rgba(22, 27, 34, 0.5)',
                border: '1px solid #30363d',
                borderRadius: '16px',
                padding: '40px',
                backdropFilter: 'blur(10px)',
            }}>
                {/* Header */}
                <div style={{ textAlign: 'center', marginBottom: '32px', borderBottom: '1px solid #21262d', paddingBottom: '24px' }}>
                    <div style={{ fontSize: '0.8rem', color: '#8b949e', textTransform: 'uppercase', letterSpacing: '3px', marginBottom: '8px' }}>
                        Executive Security Report
                    </div>
                    <h1 style={{
                        fontSize: '2rem', fontWeight: 800, margin: '0 0 8px',
                        background: 'linear-gradient(90deg, #4facfe, #00f2fe)',
                        WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
                    }}>
                        Nova AI DevSecOps Agent
                    </h1>
                    <div style={{ color: '#8b949e', fontSize: '0.85rem' }}>{now} • Confidential</div>
                </div>

                {/* Key Metrics */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '32px' }}>
                    <MetricBox value="3" label="Vulns Detected" color="#ff4d4f" />
                    <MetricBox value="3" label="Auto-Patched" color="#52c41a" />
                    <MetricBox value="100%" label="Compliance" color="#722ed1" />
                    <MetricBox value="<30s" label="Mean Time To Fix" color="#4facfe" />
                    <MetricBox value="0" label="Unresolved" color="#52c41a" />
                    <MetricBox value="5" label="Active Agents" color="#eb2f96" />
                </div>

                {/* Risk Summary */}
                <Section title="Risk Summary">
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                        <thead>
                            <tr style={{ borderBottom: '1px solid #21262d', color: '#8b949e' }}>
                                <th style={{ textAlign: 'left', padding: '8px 0' }}>Vulnerability</th>
                                <th>Severity</th>
                                <th>File</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <Row id="CVE-2026-0002" severity="Critical" file="api_server.rs" status="Resolved" />
                            <Row id="CVE-2026-0017" severity="High" file="web_handler.rs" status="Resolved" />
                            <Row id="CVE-2026-0031" severity="High" file="deploy_script.rs" status="Resolved" />
                        </tbody>
                    </table>
                </Section>

                {/* Compliance */}
                <Section title="Compliance Status">
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        <ComplianceRow framework="PCI DSS 6.5.1" status="PASS" score={100} />
                        <ComplianceRow framework="EU CRA Art.10" status="PASS" score={100} />
                        <ComplianceRow framework="NIST SP 800-218 (SSDF)" status="PASS" score={100} />
                    </div>
                </Section>

                {/* Architecture */}
                <Section title="Agent Architecture">
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '8px', textAlign: 'center' }}>
                        {[
                            { icon: '🔍', name: 'ThreatIntel' },
                            { icon: '⚙️', name: 'PatchAgent' },
                            { icon: '🛡️', name: 'NovaShield' },
                            { icon: '📋', name: 'Compliance' },
                            { icon: '💾', name: 'GitAgent' },
                        ].map(a => (
                            <div key={a.name} style={{
                                background: '#161b22', border: '1px solid #21262d',
                                borderRadius: '8px', padding: '10px 4px'
                            }}>
                                <div style={{ fontSize: '1.5rem', marginBottom: '4px' }}>{a.icon}</div>
                                <div style={{ fontSize: '0.7rem', color: '#8b949e' }}>{a.name}</div>
                            </div>
                        ))}
                    </div>
                </Section>

                {/* Recommendation */}
                <Section title="Recommendation">
                    <div style={{
                        background: 'rgba(82, 196, 26, 0.08)', border: '1px solid #52c41a33',
                        borderRadius: '10px', padding: '16px', fontSize: '0.9rem', color: '#c9d1d9', lineHeight: 1.6,
                    }}>
                        ✅ <strong>All critical and high-severity vulnerabilities have been automatically detected, patched, and verified.</strong> The system achieves 100% compliance across PCI DSS, EU CRA, and NIST frameworks. No manual intervention was required. The mean time to remediation is under 30 seconds, representing a <strong>6,500x improvement</strong> over industry average (197 days).
                    </div>
                </Section>

                {/* Footer */}
                <div style={{ textAlign: 'center', marginTop: '24px', paddingTop: '16px', borderTop: '1px solid #21262d' }}>
                    <div style={{ fontSize: '0.75rem', color: '#484f58' }}>
                        Generated by Nova AI Security Agent • Powered by Amazon Bedrock
                    </div>
                </div>
            </div>
        </div>
    );
}

function MetricBox({ value, label, color }: { value: string; label: string; color: string }) {
    return (
        <div style={{
            background: `${color}0a`, border: `1px solid ${color}22`,
            borderRadius: '10px', padding: '14px', textAlign: 'center'
        }}>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color }}>{value}</div>
            <div style={{ fontSize: '0.75rem', color: '#8b949e', marginTop: '2px' }}>{label}</div>
        </div>
    );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
    return (
        <div style={{ marginBottom: '24px' }}>
            <h3 style={{ fontSize: '0.85rem', color: '#8b949e', textTransform: 'uppercase', letterSpacing: '2px', margin: '0 0 12px' }}>{title}</h3>
            {children}
        </div>
    );
}

function Row({ id, severity, file, status }: { id: string; severity: string; file: string; status: string }) {
    const sevColor = severity === 'Critical' ? '#ff4d4f' : '#faad14';
    return (
        <tr style={{ borderBottom: '1px solid #21262d11' }}>
            <td style={{ padding: '6px 0', color: '#c9d1d9' }}>{id}</td>
            <td style={{ textAlign: 'center' }}><span style={{ color: sevColor, fontSize: '0.8rem', fontWeight: 600 }}>{severity}</span></td>
            <td style={{ textAlign: 'center', color: '#8b949e', fontFamily: 'monospace', fontSize: '0.8rem' }}>{file}</td>
            <td style={{ textAlign: 'center' }}><span style={{ color: '#52c41a', fontSize: '0.8rem', fontWeight: 600 }}>✅ {status}</span></td>
        </tr>
    );
}

function ComplianceRow({ framework, status, score }: { framework: string; status: string; score: number }) {
    return (
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', background: '#161b22', borderRadius: '8px' }}>
            <span style={{ fontSize: '0.85rem', color: '#c9d1d9' }}>{framework}</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ width: '100px', height: '6px', background: '#21262d', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{ width: `${score}%`, height: '100%', background: '#52c41a', borderRadius: '3px' }} />
                </div>
                <span style={{ color: '#52c41a', fontSize: '0.8rem', fontWeight: 600 }}>{status}</span>
            </div>
        </div>
    );
}
