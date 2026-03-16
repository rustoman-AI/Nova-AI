import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen, Event } from '@tauri-apps/api/event';

export default function SecurityToolsPanel() {
    const [activeTab, setActiveTab] = useState<'chat' | 'sbom' | 'cicd' | 'heatmap' | 'score' | 'readme' | 'notify'>('score');
    const [chatMessages, setChatMessages] = useState<{role: 'user' | 'ai'; text: string}[]>([]);
    const [chatInput, setChatInput] = useState('');
    const [chatLoading, setChatLoading] = useState(false);
    const [sbomData, setSbomData] = useState<string | null>(null);
    const [cicdData, setCicdData] = useState<string | null>(null);
    const [readmeData, setReadmeData] = useState<string | null>(null);
    const [notificationsEnabled, setNotificationsEnabled] = useState(false);
    const [notifications, setNotifications] = useState<{title: string; body: string; time: string}[]>([]);

    // Listen for desktop notifications
    useEffect(() => {
        if (!notificationsEnabled) return;
        const unlisten = listen<any>('swarm-event', (e: Event<any>) => {
            const ev = e.payload;
            if (ev.type === 'ThreatDetected') {
                const n = { title: '🛑 Threat Detected', body: `${ev.vuln_id} in ${ev.node_id}`, time: new Date().toLocaleTimeString() };
                setNotifications(prev => [n, ...prev].slice(0, 20));
                if (Notification.permission === 'granted') new Notification(n.title, { body: n.body });
            } else if (ev.type === 'PatchApplied') {
                const n = { title: '✅ Patch Applied', body: `Committed ${ev.commit_id?.substring(0, 8)}`, time: new Date().toLocaleTimeString() };
                setNotifications(prev => [n, ...prev].slice(0, 20));
                if (Notification.permission === 'granted') new Notification(n.title, { body: n.body });
            }
        });
        return () => { unlisten.then(f => f()); };
    }, [notificationsEnabled]);

    const sendChat = async () => {
        if (!chatInput.trim() || chatLoading) return;
        const msg = chatInput;
        setChatInput('');
        setChatMessages(prev => [...prev, { role: 'user', text: msg }]);
        setChatLoading(true);
        try {
            const res = await invoke<string>('chat_with_nova', { message: msg });
            setChatMessages(prev => [...prev, { role: 'ai', text: res }]);
        } catch(e) {
            setChatMessages(prev => [...prev, { role: 'ai', text: 'Error: ' + e }]);
        }
        setChatLoading(false);
    };

    const loadSbom = async () => {
        try { setSbomData(await invoke<string>('generate_sbom')); } catch(e) { console.error(e); }
    };

    const loadCicd = async () => {
        try { setCicdData(await invoke<string>('generate_cicd_pipeline')); } catch(e) { console.error(e); }
    };

    const loadReadme = async () => {
        try { setReadmeData(await invoke<string>('generate_security_readme')); } catch(e) { console.error(e); }
    };

    const tabs = [
        { id: 'score' as const, label: '📈 Security Score', icon: '📈' },
        { id: 'chat' as const, label: '💬 Nova Chat', icon: '💬' },
        { id: 'sbom' as const, label: '📦 SBOM', icon: '📦' },
        { id: 'cicd' as const, label: '🔗 CI/CD', icon: '🔗' },
        { id: 'heatmap' as const, label: '🗺️ Heatmap', icon: '🗺️' },
        { id: 'readme' as const, label: '📜 README', icon: '📜' },
        { id: 'notify' as const, label: '🔔 Alerts', icon: '🔔' },
    ];

    return (
        <div style={{
            padding: '20px',
            minHeight: '100vh',
            background: 'radial-gradient(ellipse at bottom, #0d1117 0%, #03040b 100%)',
            color: '#fff',
            fontFamily: "'Inter', -apple-system, sans-serif"
        }}>
            {/* Tab Bar */}
            <div style={{ display: 'flex', gap: '8px', marginBottom: '20px', flexWrap: 'wrap' }}>
                {tabs.map(t => (
                    <button key={t.id} onClick={() => { 
                        setActiveTab(t.id);
                        if (t.id === 'sbom' && !sbomData) loadSbom();
                        if (t.id === 'cicd' && !cicdData) loadCicd();
                        if (t.id === 'readme' && !readmeData) loadReadme();
                    }} style={{
                        background: activeTab === t.id ? 'rgba(79, 172, 254, 0.15)' : 'rgba(22, 27, 34, 0.6)',
                        border: `1px solid ${activeTab === t.id ? '#4facfe44' : '#21262d'}`,
                        color: activeTab === t.id ? '#4facfe' : '#8b949e',
                        padding: '10px 18px',
                        borderRadius: '10px',
                        cursor: 'pointer',
                        fontSize: '0.85rem',
                        fontWeight: 600,
                        transition: 'all 0.2s',
                    }}>
                        {t.label}
                    </button>
                ))}
            </div>

            <div style={{
                background: 'rgba(22, 27, 34, 0.4)',
                border: '1px solid #30363d',
                borderRadius: '16px',
                padding: '24px',
                backdropFilter: 'blur(10px)',
                minHeight: '500px'
            }}>
                {/* Security Score Radar */}
                {activeTab === 'score' && <SecurityScoreRadar />}

                {/* Chat */}
                {activeTab === 'chat' && (
                    <div>
                        <h2 style={{ margin: '0 0 16px', fontSize: '1.3rem' }}>💬 Chat with Nova AI</h2>
                        <div style={{
                            height: '350px',
                            overflowY: 'auto',
                            background: '#0d1117',
                            borderRadius: '10px',
                            padding: '16px',
                            marginBottom: '12px',
                            border: '1px solid #21262d',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '10px'
                        }}>
                            {chatMessages.length === 0 && (
                                <div style={{ color: '#484f58', textAlign: 'center', padding: '60px 0', fontStyle: 'italic' }}>
                                    Ask Nova anything about security, compliance, or your codebase...
                                </div>
                            )}
                            {chatMessages.map((m, i) => (
                                <div key={i} style={{
                                    alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
                                    maxWidth: '75%',
                                    padding: '10px 14px',
                                    borderRadius: m.role === 'user' ? '14px 14px 4px 14px' : '14px 14px 14px 4px',
                                    background: m.role === 'user' ? 'rgba(79, 172, 254, 0.15)' : 'rgba(82, 196, 26, 0.1)',
                                    border: `1px solid ${m.role === 'user' ? '#4facfe33' : '#52c41a33'}`,
                                    fontSize: '0.9rem',
                                    whiteSpace: 'pre-wrap',
                                    lineHeight: 1.5
                                }}>
                                    <span style={{ fontSize: '0.7rem', color: '#8b949e', display: 'block', marginBottom: 4 }}>
                                        {m.role === 'user' ? '👤 You' : '🧠 Nova AI'}
                                    </span>
                                    {m.text}
                                </div>
                            ))}
                            {chatLoading && (
                                <div style={{ color: '#8b949e', fontStyle: 'italic' }}>🧠 Nova is thinking...</div>
                            )}
                        </div>
                        <div style={{ display: 'flex', gap: '8px' }}>
                            <input
                                value={chatInput}
                                onChange={e => setChatInput(e.target.value)}
                                onKeyDown={e => e.key === 'Enter' && sendChat()}
                                placeholder="Ask Nova a security question..."
                                style={{
                                    flex: 1,
                                    background: '#0d1117',
                                    border: '1px solid #30363d',
                                    borderRadius: '10px',
                                    padding: '12px 16px',
                                    color: '#fff',
                                    fontSize: '0.9rem',
                                    outline: 'none'
                                }}
                            />
                            <button onClick={sendChat} style={{
                                background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
                                border: 'none',
                                borderRadius: '10px',
                                padding: '12px 20px',
                                color: '#fff',
                                fontWeight: 700,
                                cursor: 'pointer'
                            }}>Send</button>
                        </div>
                    </div>
                )}

                {/* SBOM */}
                {activeTab === 'sbom' && (
                    <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                            <h2 style={{ margin: 0, fontSize: '1.3rem' }}>📦 CycloneDX SBOM (v1.5)</h2>
                            {sbomData && (
                                <button onClick={() => {
                                    const blob = new Blob([sbomData], { type: 'application/json' });
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement('a'); a.href = url; a.download = 'sbom.cdx.json'; a.click();
                                }} style={{
                                    background: 'rgba(82, 196, 26, 0.15)',
                                    border: '1px solid #52c41a44',
                                    color: '#52c41a',
                                    padding: '8px 16px',
                                    borderRadius: '8px',
                                    cursor: 'pointer',
                                    fontWeight: 600,
                                    fontSize: '0.85rem'
                                }}>⬇️ Download JSON</button>
                            )}
                        </div>
                        <pre style={{
                            background: '#0d1117',
                            border: '1px solid #21262d',
                            borderRadius: '10px',
                            padding: '16px',
                            fontSize: '0.8rem',
                            color: '#c9d1d9',
                            overflowX: 'auto',
                            maxHeight: '450px',
                            overflowY: 'auto',
                            lineHeight: 1.4
                        }}>
                            {sbomData || 'Loading SBOM...'}
                        </pre>
                    </div>
                )}

                {/* CI/CD */}
                {activeTab === 'cicd' && (
                    <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                            <h2 style={{ margin: 0, fontSize: '1.3rem' }}>🔗 GitHub Actions Pipeline</h2>
                            {cicdData && (
                                <button onClick={() => {
                                    const blob = new Blob([cicdData], { type: 'text/yaml' });
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement('a'); a.href = url; a.download = 'security.yml'; a.click();
                                }} style={{
                                    background: 'rgba(79, 172, 254, 0.15)',
                                    border: '1px solid #4facfe44',
                                    color: '#4facfe',
                                    padding: '8px 16px',
                                    borderRadius: '8px',
                                    cursor: 'pointer',
                                    fontWeight: 600,
                                    fontSize: '0.85rem'
                                }}>⬇️ Download YAML</button>
                            )}
                        </div>
                        <pre style={{
                            background: '#0d1117',
                            border: '1px solid #21262d',
                            borderRadius: '10px',
                            padding: '16px',
                            fontSize: '0.8rem',
                            color: '#c9d1d9',
                            overflowX: 'auto',
                            maxHeight: '450px',
                            lineHeight: 1.4
                        }}>
                            {cicdData || 'Generating pipeline...'}
                        </pre>
                    </div>
                )}

                {/* Attack Surface Heatmap */}
                {activeTab === 'heatmap' && <AttackSurfaceHeatmap />}

                {/* Security README */}
                {activeTab === 'readme' && (
                    <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                            <h2 style={{ margin: 0, fontSize: '1.3rem' }}>📜 SECURITY.md</h2>
                            {readmeData && (
                                <button onClick={() => {
                                    const blob = new Blob([readmeData], { type: 'text/markdown' });
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement('a'); a.href = url; a.download = 'SECURITY.md'; a.click();
                                }} style={{
                                    background: 'rgba(114, 46, 209, 0.15)',
                                    border: '1px solid #722ed144',
                                    color: '#b37feb',
                                    padding: '8px 16px',
                                    borderRadius: '8px',
                                    cursor: 'pointer',
                                    fontWeight: 600,
                                    fontSize: '0.85rem'
                                }}>⬇️ Download SECURITY.md</button>
                            )}
                        </div>
                        <pre style={{
                            background: '#0d1117',
                            border: '1px solid #21262d',
                            borderRadius: '10px',
                            padding: '16px',
                            fontSize: '0.8rem',
                            color: '#c9d1d9',
                            overflowX: 'auto',
                            maxHeight: '450px',
                            overflowY: 'auto',
                            lineHeight: 1.5,
                            whiteSpace: 'pre-wrap'
                        }}>
                            {readmeData || 'Generating SECURITY.md...'}
                        </pre>
                    </div>
                )}

                {/* Notifications */}
                {activeTab === 'notify' && (
                    <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                            <h2 style={{ margin: 0, fontSize: '1.3rem' }}>🔔 Desktop Alerts</h2>
                            <button onClick={() => {
                                if (!notificationsEnabled) Notification.requestPermission();
                                setNotificationsEnabled(v => !v);
                            }} style={{
                                background: notificationsEnabled ? 'rgba(82, 196, 26, 0.15)' : 'rgba(139, 148, 158, 0.1)',
                                border: `1px solid ${notificationsEnabled ? '#52c41a44' : '#30363d'}`,
                                color: notificationsEnabled ? '#52c41a' : '#8b949e',
                                padding: '10px 20px',
                                borderRadius: '8px',
                                cursor: 'pointer',
                                fontWeight: 600,
                            }}>
                                {notificationsEnabled ? '🔔 Alerts ON' : '🔕 Alerts OFF'}
                            </button>
                        </div>
                        <p style={{ color: '#8b949e', fontSize: '0.85rem', marginBottom: '16px' }}>
                            When enabled, you'll receive native desktop notifications for threats and patches.
                        </p>
                        {notifications.length === 0 ? (
                            <div style={{ textAlign: 'center', padding: '60px 0', color: '#484f58', fontStyle: 'italic' }}>
                                {notificationsEnabled ? 'Waiting for swarm events...' : 'Enable alerts to start receiving notifications'}
                            </div>
                        ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                {notifications.map((n, i) => (
                                    <div key={i} style={{
                                        background: '#161b22',
                                        border: '1px solid #21262d',
                                        borderRadius: '8px',
                                        padding: '12px 16px',
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        alignItems: 'center'
                                    }}>
                                        <div>
                                            <strong style={{ fontSize: '0.9rem' }}>{n.title}</strong>
                                            <div style={{ color: '#8b949e', fontSize: '0.8rem', marginTop: 2 }}>{n.body}</div>
                                        </div>
                                        <span style={{ color: '#484f58', fontSize: '0.75rem' }}>{n.time}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}

function SecurityScoreRadar() {
    const metrics = [
        { label: 'Code Quality', score: 92, color: '#4facfe' },
        { label: 'Dependencies', score: 87, color: '#eb2f96' },
        { label: 'Compliance', score: 100, color: '#722ed1' },
        { label: 'Vuln Coverage', score: 95, color: '#52c41a' },
        { label: 'SBOM Coverage', score: 100, color: '#13c2c2' },
        { label: 'CI/CD Maturity', score: 78, color: '#faad14' },
    ];
    const overall = Math.round(metrics.reduce((sum, m) => sum + m.score, 0) / metrics.length);

    // Calculate radar polygon
    const cx = 150, cy = 150, r = 110;
    const angleStep = (Math.PI * 2) / metrics.length;
    const points = metrics.map((m, i) => {
        const angle = -Math.PI / 2 + i * angleStep;
        const dist = (m.score / 100) * r;
        return { x: cx + Math.cos(angle) * dist, y: cy + Math.sin(angle) * dist };
    });
    const polygonPoints = points.map(p => `${p.x},${p.y}`).join(' ');

    return (
        <div>
            <h2 style={{ margin: '0 0 20px', fontSize: '1.3rem' }}>📈 Security Score</h2>
            <div style={{ display: 'flex', gap: '30px', flexWrap: 'wrap', alignItems: 'center' }}>
                <svg width="300" height="300" viewBox="0 0 300 300">
                    {/* Background rings */}
                    {[0.25, 0.5, 0.75, 1].map(scale => (
                        <circle key={scale} cx={cx} cy={cy} r={r * scale}
                            fill="none" stroke="#21262d" strokeWidth={1} />
                    ))}
                    {/* Axis lines */}
                    {metrics.map((_, i) => {
                        const angle = -Math.PI / 2 + i * angleStep;
                        return <line key={i} x1={cx} y1={cy}
                            x2={cx + Math.cos(angle) * r} y2={cy + Math.sin(angle) * r}
                            stroke="#21262d" strokeWidth={1} />;
                    })}
                    {/* Score polygon */}
                    <polygon points={polygonPoints} fill="rgba(79, 172, 254, 0.15)" stroke="#4facfe" strokeWidth={2} />
                    {/* Score dots + labels */}
                    {metrics.map((m, i) => {
                        const angle = -Math.PI / 2 + i * angleStep;
                        const labelDist = r + 20;
                        return (
                            <g key={i}>
                                <circle cx={points[i].x} cy={points[i].y} r={4} fill={m.color} />
                                <text
                                    x={cx + Math.cos(angle) * labelDist}
                                    y={cy + Math.sin(angle) * labelDist}
                                    textAnchor="middle" dominantBaseline="middle"
                                    fill="#8b949e" fontSize="10" fontWeight="600"
                                >{m.label}</text>
                            </g>
                        );
                    })}
                    {/* Center score */}
                    <text x={cx} y={cy - 8} textAnchor="middle" fill="#fff" fontSize="32" fontWeight="800">{overall}</text>
                    <text x={cx} y={cy + 14} textAnchor="middle" fill="#8b949e" fontSize="11">OVERALL</text>
                </svg>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', flex: 1, minWidth: '250px' }}>
                    {metrics.map(m => (
                        <div key={m.label} style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                            <span style={{ width: '120px', fontSize: '0.85rem', color: '#8b949e' }}>{m.label}</span>
                            <div style={{ flex: 1, height: '8px', background: '#21262d', borderRadius: '4px', overflow: 'hidden' }}>
                                <div style={{
                                    width: `${m.score}%`, height: '100%',
                                    background: `linear-gradient(90deg, ${m.color}aa, ${m.color})`,
                                    borderRadius: '4px',
                                    transition: 'width 1s ease'
                                }} />
                            </div>
                            <span style={{ width: '35px', fontSize: '0.85rem', fontWeight: 700, color: m.color, textAlign: 'right' }}>{m.score}%</span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}

function AttackSurfaceHeatmap() {
    const files = [
        { name: 'api_server.rs', risk: 95, vulns: 1, status: 'patched' as const },
        { name: 'mock_vulnerable_service.rs', risk: 90, vulns: 2, status: 'patched' as const },
        { name: 'nova_client.rs', risk: 35, vulns: 0, status: 'clean' as const },
        { name: 'nova_shield.rs', risk: 20, vulns: 0, status: 'clean' as const },
        { name: 'git_agent.rs', risk: 15, vulns: 0, status: 'clean' as const },
        { name: 'actor_registry.rs', risk: 10, vulns: 0, status: 'clean' as const },
        { name: 'sbom_graph.rs', risk: 25, vulns: 0, status: 'clean' as const },
        { name: 'supply_chain.rs', risk: 40, vulns: 0, status: 'clean' as const },
        { name: 'trust_graph.rs', risk: 30, vulns: 0, status: 'clean' as const },
        { name: 'unified_graph.rs', risk: 20, vulns: 0, status: 'clean' as const },
        { name: 'attack_graph.rs', risk: 45, vulns: 0, status: 'clean' as const },
        { name: 'query_engine.rs', risk: 50, vulns: 0, status: 'clean' as const },
        { name: 'cross_pipeline.rs', risk: 30, vulns: 0, status: 'clean' as const },
        { name: 'meta_graph.rs', risk: 15, vulns: 0, status: 'clean' as const },
        { name: 'lib.rs', risk: 55, vulns: 0, status: 'clean' as const },
        { name: 'commands.rs', risk: 25, vulns: 0, status: 'clean' as const },
    ];

    const riskColor = (risk: number) => {
        if (risk >= 80) return '#ff4d4f';
        if (risk >= 50) return '#faad14';
        if (risk >= 30) return '#4facfe';
        return '#52c41a';
    };

    return (
        <div>
            <h2 style={{ margin: '0 0 16px', fontSize: '1.3rem' }}>🗺️ Attack Surface Heatmap</h2>
            <div style={{ display: 'flex', gap: '16px', marginBottom: '16px', fontSize: '0.8rem', color: '#8b949e' }}>
                <span><span style={{ color: '#ff4d4f' }}>●</span> Critical (80+)</span>
                <span><span style={{ color: '#faad14' }}>●</span> Medium (50-79)</span>
                <span><span style={{ color: '#4facfe' }}>●</span> Low (30-49)</span>
                <span><span style={{ color: '#52c41a' }}>●</span> Safe (&lt;30)</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '8px' }}>
                {files.sort((a, b) => b.risk - a.risk).map(f => (
                    <div key={f.name} style={{
                        background: `${riskColor(f.risk)}11`,
                        border: `1px solid ${riskColor(f.risk)}33`,
                        borderRadius: '10px',
                        padding: '12px',
                        position: 'relative',
                        overflow: 'hidden'
                    }}>
                        {/* Risk bar */}
                        <div style={{
                            position: 'absolute',
                            bottom: 0, left: 0,
                            width: '100%',
                            height: `${f.risk}%`,
                            background: `${riskColor(f.risk)}0a`,
                            transition: 'height 1s ease'
                        }} />
                        <div style={{ position: 'relative', zIndex: 1 }}>
                            <div style={{ fontSize: '0.78rem', fontWeight: 600, color: '#c9d1d9', marginBottom: 4 }}>
                                {f.name}
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ fontSize: '1.3rem', fontWeight: 700, color: riskColor(f.risk) }}>
                                    {f.risk}
                                </span>
                                {f.status === 'patched' && (
                                    <span style={{
                                        fontSize: '0.65rem',
                                        background: '#52c41a22',
                                        color: '#52c41a',
                                        padding: '2px 6px',
                                        borderRadius: '4px',
                                        fontWeight: 600
                                    }}>PATCHED</span>
                                )}
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}
