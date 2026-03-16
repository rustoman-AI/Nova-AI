import { useState, useEffect, useRef } from 'react';
import { listen, Event } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';

// ============================================================
//  AGENT PERFORMANCE PROFILER
// ============================================================
type AgentMetric = {
    name: string;
    icon: string;
    color: string;
    latencyMs: number;
    tokensUsed: number;
    calls: number;
    sparkline: number[];
};

function AgentProfiler() {
    const [metrics, setMetrics] = useState<AgentMetric[]>([
        { name: 'ThreatIntel', icon: '🔍', color: '#ff4d4f', latencyMs: 0, tokensUsed: 0, calls: 0, sparkline: [] },
        { name: 'PatchAgent', icon: '⚙️', color: '#eb2f96', latencyMs: 0, tokensUsed: 0, calls: 0, sparkline: [] },
        { name: 'NovaShield', icon: '🛡️', color: '#13c2c2', latencyMs: 0, tokensUsed: 0, calls: 0, sparkline: [] },
        { name: 'ComplianceBot', icon: '📋', color: '#722ed1', latencyMs: 0, tokensUsed: 0, calls: 0, sparkline: [] },
        { name: 'GitAgent', icon: '💾', color: '#52c41a', latencyMs: 0, tokensUsed: 0, calls: 0, sparkline: [] },
    ]);
    const startRef = useRef<Record<string, number>>({});

    useEffect(() => {
        const unlisten = listen<any>('swarm-event', (event: Event<any>) => {
            const ev = event.payload;
            const now = Date.now();
            const agentMap: Record<string, string> = {
                'ThreatDetected': 'ThreatIntel',
                'ReviewRequested': 'PatchAgent',
                'ReviewResult': 'NovaShield',
                'ComplianceResult': 'ComplianceBot',
                'PatchApplied': 'GitAgent',
            };
            const agent = agentMap[ev.type] || (ev.agent as string);
            if (!agent) return;

            if (!startRef.current[agent]) startRef.current[agent] = now;
            const elapsed = now - startRef.current[agent];
            startRef.current[agent] = now;
            const tokens = ev.type === 'ReviewRequested' ? 1200 + Math.floor(Math.random() * 400) :
                           ev.type === 'ReviewResult' ? 800 + Math.floor(Math.random() * 300) :
                           ev.type === 'ComplianceResult' ? 600 : 0;

            setMetrics(prev => prev.map(m => {
                if (m.name !== agent) return m;
                const newLatency = m.calls === 0 ? elapsed : Math.round((m.latencyMs * m.calls + elapsed) / (m.calls + 1));
                return {
                    ...m,
                    latencyMs: Math.min(newLatency, 5000),
                    tokensUsed: m.tokensUsed + tokens,
                    calls: m.calls + 1,
                    sparkline: [...m.sparkline.slice(-11), elapsed].slice(-12),
                };
            }));
        });
        return () => { unlisten.then(f => f()); };
    }, []);

    const maxLatency = Math.max(...metrics.map(m => m.latencyMs), 1);

    return (
        <div>
            <h3 style={{ color: '#8b949e', margin: '0 0 16px', fontSize: '0.9rem', textTransform: 'uppercase', letterSpacing: '2px' }}>
                ⏱️ Agent Performance Profiler
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {metrics.map(m => (
                    <div key={m.name} style={{
                        background: '#161b22',
                        border: '1px solid #21262d',
                        borderRadius: '10px',
                        padding: '14px 18px',
                        display: 'grid',
                        gridTemplateColumns: '140px 1fr 100px 100px 120px',
                        alignItems: 'center',
                        gap: '12px'
                    }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ fontSize: '1.1rem' }}>{m.icon}</span>
                            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: m.color }}>{m.name}</span>
                        </div>
                        {/* Latency bar */}
                        <div style={{ height: '8px', background: '#21262d', borderRadius: '4px', overflow: 'hidden' }}>
                            <div style={{
                                width: `${(m.latencyMs / maxLatency) * 100}%`,
                                height: '100%',
                                background: `linear-gradient(90deg, ${m.color}88, ${m.color})`,
                                borderRadius: '4px',
                                transition: 'width 0.5s ease'
                            }} />
                        </div>
                        <span style={{ fontSize: '0.8rem', color: '#c9d1d9', textAlign: 'right' }}>
                            {m.latencyMs > 0 ? `${m.latencyMs}ms` : '—'}
                        </span>
                        <span style={{ fontSize: '0.8rem', color: '#8b949e', textAlign: 'right' }}>
                            {m.tokensUsed > 0 ? `${m.tokensUsed} tok` : '—'}
                        </span>
                        {/* Sparkline */}
                        <svg width="120" height="24" viewBox="0 0 120 24">
                            {m.sparkline.length > 1 && (
                                <polyline
                                    points={m.sparkline.map((v, i) => {
                                        const x = (i / (m.sparkline.length - 1)) * 116 + 2;
                                        const maxS = Math.max(...m.sparkline, 1);
                                        const y = 22 - (v / maxS) * 20;
                                        return `${x},${y}`;
                                    }).join(' ')}
                                    fill="none" stroke={m.color} strokeWidth={1.5} opacity={0.7}
                                />
                            )}
                        </svg>
                    </div>
                ))}
            </div>
            {/* Totals */}
            <div style={{ display: 'flex', gap: '20px', marginTop: '16px', justifyContent: 'center' }}>
                <Stat label="Total Calls" value={metrics.reduce((s, m) => s + m.calls, 0).toString()} color="#4facfe" />
                <Stat label="Total Tokens" value={metrics.reduce((s, m) => s + m.tokensUsed, 0).toLocaleString()} color="#eb2f96" />
                <Stat label="Avg Latency" value={
                    metrics.filter(m => m.calls > 0).length > 0
                        ? Math.round(metrics.reduce((s, m) => s + m.latencyMs, 0) / Math.max(metrics.filter(m => m.calls > 0).length, 1)) + 'ms'
                        : '—'
                } color="#13c2c2" />
            </div>
        </div>
    );
}

function Stat({ label, value, color }: { label: string; value: string; color: string }) {
    return (
        <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color }}>{value}</div>
            <div style={{ fontSize: '0.75rem', color: '#8b949e' }}>{label}</div>
        </div>
    );
}

// ============================================================
//  MULTI-LANGUAGE VULNERABILITY DEMO
// ============================================================
function MultiLanguageDemo() {
    const vulns = [
        {
            lang: 'Rust', icon: '🦀', color: '#ff4d4f',
            vuln: 'SQL Injection',
            bad: 'let q = format!("SELECT * FROM users WHERE id = {}", id);',
            good: 'let q = "SELECT * FROM users WHERE id = $1"; // sqlx bind',
            cve: 'CVE-2026-0002'
        },
        {
            lang: 'Python', icon: '🐍', color: '#faad14',
            vuln: 'Pickle Deserialization RCE',
            bad: 'data = pickle.loads(untrusted_input)',
            good: 'data = json.loads(untrusted_input)  # safe deserialization',
            cve: 'CVE-2026-PY01'
        },
        {
            lang: 'JavaScript', icon: '🟨', color: '#4facfe',
            vuln: 'Prototype Pollution',
            bad: 'merge(target, JSON.parse(userInput))  // deep merge unsafe',
            good: 'merge(target, sanitize(JSON.parse(userInput)))  // validated',
            cve: 'CVE-2026-JS01'
        },
        {
            lang: 'Go', icon: '🐹', color: '#13c2c2',
            vuln: 'Path Traversal',
            bad: 'http.ServeFile(w, r, "/data/" + r.URL.Query().Get("file"))',
            good: 'filepath.Clean(path); if !strings.HasPrefix(p, base) { deny }',
            cve: 'CVE-2026-GO01'
        },
        {
            lang: 'C++', icon: '⚙️', color: '#f5222d',
            vuln: 'Buffer Overflow (Stack)',
            bad: 'char buf[64]; strcpy(buf, user_input);  // no bounds check',
            good: 'std::string buf(user_input);  // RAII, bounds-safe',
            cve: 'CVE-2026-CPP01'
        },
        {
            lang: 'Java', icon: '☕', color: '#ff7a45',
            vuln: 'Log4Shell Remote Code Execution',
            bad: 'logger.info("User: " + request.getHeader("X-Name"));',
            good: 'logger.info("User: {}", sanitize(header));  // no JNDI lookup',
            cve: 'CVE-2021-44228'
        },
    ];

    return (
        <div>
            <h3 style={{ color: '#8b949e', margin: '0 0 16px', fontSize: '0.9rem', textTransform: 'uppercase', letterSpacing: '2px' }}>
                🌐 Multi-Language Vulnerability Patterns
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '12px' }}>
                {vulns.map(v => (
                    <div key={v.lang} style={{
                        background: `${v.color}08`,
                        border: `1px solid ${v.color}22`,
                        borderRadius: '12px',
                        padding: '16px',
                        overflow: 'hidden'
                    }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
                            <span style={{ fontSize: '1rem', fontWeight: 700, color: v.color }}>{v.icon} {v.lang}</span>
                            <code style={{ fontSize: '0.7rem', color: '#8b949e', background: '#21262d', padding: '2px 6px', borderRadius: '4px' }}>{v.cve}</code>
                        </div>
                        <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#c9d1d9', marginBottom: 8 }}>{v.vuln}</div>
                        <div style={{ fontFamily: 'monospace', fontSize: '0.75rem', marginBottom: 4 }}>
                            <div style={{ background: 'rgba(255, 77, 79, 0.1)', color: '#ff7875', padding: '4px 8px', borderRadius: '4px', marginBottom: 4 }}>
                                - {v.bad}
                            </div>
                            <div style={{ background: 'rgba(82, 196, 26, 0.1)', color: '#95de64', padding: '4px 8px', borderRadius: '4px' }}>
                                + {v.good}
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

// ============================================================
//  THREAT TIMELINE
// ============================================================
type TimelineEvent = {
    time: string;
    type: 'threat' | 'fix' | 'audit' | 'commit';
    title: string;
    detail: string;
};

function ThreatTimeline() {
    const [events, setEvents] = useState<TimelineEvent[]>([]);

    useEffect(() => {
        const unlisten = listen<any>('swarm-event', (event: Event<any>) => {
            const ev = event.payload;
            const time = new Date().toLocaleTimeString();
            let entry: TimelineEvent | null = null;

            switch (ev.type) {
                case 'ThreatDetected':
                    entry = { time, type: 'threat', title: `${ev.vuln_id} detected`, detail: ev.description || ev.node_id };
                    break;
                case 'ReviewResult':
                    if (ev.approved) entry = { time, type: 'fix', title: `Patch approved for ${ev.vuln_id}`, detail: ev.feedback?.substring(0, 60) || '' };
                    break;
                case 'PatchApplied':
                    entry = { time, type: 'commit', title: `Committed ${ev.commit_id?.substring(0, 8)}`, detail: ev.file_path };
                    break;
                case 'ComplianceResult':
                    entry = { time, type: 'audit', title: `Compliance: ${(ev as any).passed ? 'PASSED' : 'FAILED'}`, detail: `Score: ${(ev as any).score}%` };
                    break;
            }
            if (entry) setEvents(prev => [...prev, entry!]);
        });
        return () => { unlisten.then(f => f()); };
    }, []);

    const typeConfig = {
        threat: { icon: '🔴', color: '#ff4d4f', line: '#ff4d4f' },
        fix:    { icon: '🟢', color: '#52c41a', line: '#52c41a' },
        commit: { icon: '🔵', color: '#4facfe', line: '#4facfe' },
        audit:  { icon: '🟣', color: '#722ed1', line: '#722ed1' },
    };

    return (
        <div>
            <h3 style={{ color: '#8b949e', margin: '0 0 16px', fontSize: '0.9rem', textTransform: 'uppercase', letterSpacing: '2px' }}>
                📊 Threat Timeline
            </h3>
            {events.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '50px 0', color: '#484f58', fontStyle: 'italic' }}>
                    Run a demo to see events appear on the timeline...
                </div>
            ) : (
                <div style={{ position: 'relative', paddingLeft: '30px' }}>
                    {/* Vertical line */}
                    <div style={{ position: 'absolute', left: '14px', top: 0, bottom: 0, width: '2px', background: '#21262d' }} />
                    {events.map((e, i) => {
                        const cfg = typeConfig[e.type];
                        return (
                            <div key={i} style={{ display: 'flex', gap: '14px', marginBottom: '14px', animation: 'fadeSlideIn 0.3s ease-out' }}>
                                <div style={{
                                    position: 'relative', zIndex: 1,
                                    width: '12px', height: '12px', borderRadius: '50%',
                                    background: cfg.color, marginTop: '4px', marginLeft: '-21px',
                                    boxShadow: `0 0 8px ${cfg.color}66`
                                }} />
                                <div style={{ flex: 1 }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                        <span style={{ fontSize: '0.85rem', fontWeight: 600, color: cfg.color }}>{cfg.icon} {e.title}</span>
                                        <span style={{ fontSize: '0.7rem', color: '#484f58' }}>{e.time}</span>
                                    </div>
                                    <div style={{ fontSize: '0.78rem', color: '#8b949e', marginTop: 2 }}>{e.detail}</div>
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}
            <style>{`@keyframes fadeSlideIn { from { opacity: 0; transform: translateX(-10px); } to { opacity: 1; transform: translateX(0); } }`}</style>
        </div>
    );
}

// ============================================================
//  ACHIEVEMENTS SYSTEM
// ============================================================
function AchievementsPanel() {
    const [unlocked, setUnlocked] = useState<Set<string>>(new Set());

    const achievements = [
        { id: 'first_threat',   icon: '🩸', title: 'First Blood',        desc: 'Detected your first vulnerability', trigger: 'ThreatDetected' },
        { id: 'first_fix',      icon: '🔧', title: 'Patch Master',       desc: 'Successfully approved a patch', trigger: 'ReviewResult' },
        { id: 'git_commit',     icon: '💾', title: 'Auto Commit',        desc: 'Committed a fix automatically', trigger: 'PatchApplied' },
        { id: 'compliance',     icon: '📋', title: 'Perfect Score',      desc: '100% compliance across all frameworks', trigger: 'ComplianceResult' },
        { id: 'multi_vuln',     icon: '🔥', title: 'Triple Kill',        desc: 'Fixed 3 vulnerabilities in one session', trigger: 'multi' },
        { id: 'speed_demon',    icon: '⚡', title: 'Speed Demon',        desc: 'Fixed a vuln in under 10 seconds', trigger: 'speed' },
        { id: 'voice_on',      icon: '🎙️', title: 'Narrator',           desc: 'Enabled voice narration', trigger: 'manual' },
        { id: 'fullscreen',    icon: '🖥️', title: 'Big Screen',          desc: 'Used fullscreen pitch mode', trigger: 'manual' },
    ];

    const threatCount = useRef(0);
    const fixCount = useRef(0);
    const firstThreatTime = useRef(0);

    useEffect(() => {
        const unlisten = listen<any>('swarm-event', (event: Event<any>) => {
            const ev = event.payload;
            switch (ev.type) {
                case 'ThreatDetected':
                    threatCount.current++;
                    if (!firstThreatTime.current) firstThreatTime.current = Date.now();
                    setUnlocked(prev => new Set([...prev, 'first_threat']));
                    break;
                case 'ReviewResult':
                    if (ev.approved) {
                        fixCount.current++;
                        setUnlocked(prev => new Set([...prev, 'first_fix']));
                        if (fixCount.current >= 3) setUnlocked(prev => new Set([...prev, 'multi_vuln']));
                    }
                    break;
                case 'PatchApplied':
                    setUnlocked(prev => new Set([...prev, 'git_commit']));
                    if (firstThreatTime.current && (Date.now() - firstThreatTime.current) < 10000) {
                        setUnlocked(prev => new Set([...prev, 'speed_demon']));
                    }
                    break;
                case 'ComplianceResult':
                    if ((ev as any).passed) setUnlocked(prev => new Set([...prev, 'compliance']));
                    break;
            }
        });
        return () => { unlisten.then(f => f()); };
    }, []);

    return (
        <div>
            <h3 style={{ color: '#8b949e', margin: '0 0 16px', fontSize: '0.9rem', textTransform: 'uppercase', letterSpacing: '2px' }}>
                🏆 Achievements ({unlocked.size}/{achievements.length})
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '10px' }}>
                {achievements.map(a => {
                    const isUnlocked = unlocked.has(a.id);
                    return (
                        <div key={a.id} style={{
                            background: isUnlocked ? 'rgba(250, 176, 5, 0.08)' : '#161b22',
                            border: `1px solid ${isUnlocked ? '#faad1444' : '#21262d'}`,
                            borderRadius: '10px',
                            padding: '14px',
                            opacity: isUnlocked ? 1 : 0.4,
                            transition: 'all 0.5s ease',
                            position: 'relative',
                            overflow: 'hidden'
                        }}>
                            {isUnlocked && (
                                <div style={{
                                    position: 'absolute', top: 6, right: 8,
                                    fontSize: '0.65rem', color: '#faad14', fontWeight: 700,
                                    background: '#faad1422', padding: '2px 6px', borderRadius: '4px'
                                }}>UNLOCKED</div>
                            )}
                            <div style={{ fontSize: '1.8rem', marginBottom: '6px' }}>{a.icon}</div>
                            <div style={{ fontSize: '0.85rem', fontWeight: 700, color: isUnlocked ? '#faad14' : '#484f58' }}>{a.title}</div>
                            <div style={{ fontSize: '0.75rem', color: '#8b949e', marginTop: 2 }}>{a.desc}</div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

// ============================================================
//  LIVE DEMO SCRIPT (Automated Presenter Mode)
// ============================================================
function LiveDemoScript() {
    const [running, setRunning] = useState(false);
    const [step, setStep] = useState(-1);
    const [log, setLog] = useState<string[]>([]);

    const steps = [
        { label: 'Initializing AI Swarm...', duration: 2000 },
        { label: 'Launching ThreatIntel scan...', duration: 1500, action: 'replay_demo' },
        { label: 'Monitoring agents...', duration: 25000 },
        { label: 'Demo complete! ✅', duration: 0 },
    ];

    const runDemo = async () => {
        setRunning(true);
        setLog([]);
        for (let i = 0; i < steps.length; i++) {
            setStep(i);
            setLog(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${steps[i].label}`]);
            if (steps[i].action) {
                try { await invoke(steps[i].action!); } catch(e) { console.error(e); }
            }
            if (steps[i].duration > 0) {
                await new Promise(r => setTimeout(r, steps[i].duration));
            }
        }
        setRunning(false);
    };

    return (
        <div>
            <h3 style={{ color: '#8b949e', margin: '0 0 16px', fontSize: '0.9rem', textTransform: 'uppercase', letterSpacing: '2px' }}>
                🎯 Live Demo Script
            </h3>
            <div style={{ textAlign: 'center', marginBottom: '20px' }}>
                <button onClick={runDemo} disabled={running} style={{
                    background: running
                        ? 'rgba(139, 148, 158, 0.1)'
                        : 'linear-gradient(135deg, #eb2f96 0%, #722ed1 100%)',
                    border: 'none',
                    padding: '14px 36px',
                    borderRadius: '12px',
                    color: '#fff',
                    fontSize: '1.1rem',
                    fontWeight: 700,
                    cursor: running ? 'not-allowed' : 'pointer',
                    letterSpacing: '1px',
                    boxShadow: running ? 'none' : '0 4px 20px rgba(235, 47, 150, 0.3)',
                }}>
                    {running ? '⏳ Running...' : '▶️ START FULL DEMO'}
                </button>
            </div>
            {/* Progress */}
            {step >= 0 && (
                <div style={{ marginBottom: '16px' }}>
                    <div style={{ display: 'flex', gap: '4px', marginBottom: '8px' }}>
                        {steps.map((_, i) => (
                            <div key={i} style={{
                                flex: 1, height: '4px', borderRadius: '2px',
                                background: i <= step ? '#eb2f96' : '#21262d',
                                transition: 'background 0.3s'
                            }} />
                        ))}
                    </div>
                    <div style={{ fontSize: '0.85rem', color: '#eb2f96', textAlign: 'center', fontWeight: 600 }}>
                        Step {step + 1}/{steps.length}: {steps[step]?.label}
                    </div>
                </div>
            )}
            {/* Log */}
            {log.length > 0 && (
                <div style={{
                    background: '#0d1117', border: '1px solid #21262d', borderRadius: '10px',
                    padding: '12px', maxHeight: '200px', overflowY: 'auto', fontFamily: 'monospace', fontSize: '0.8rem'
                }}>
                    {log.map((l, i) => <div key={i} style={{ color: '#8b949e', marginBottom: 2 }}>{l}</div>)}
                </div>
            )}
        </div>
    );
}

// ============================================================
//  MAIN EXPORT: Combined Panel
// ============================================================
export default function AdvancedFeaturesPanel() {
    const [activeSection, setActiveSection] = useState<'profiler' | 'multilang' | 'timeline' | 'achievements' | 'demo'>('profiler');

    const sections = [
        { id: 'profiler' as const, label: '⏱️ Profiler' },
        { id: 'multilang' as const, label: '🌐 Multi-Lang' },
        { id: 'timeline' as const, label: '📊 Timeline' },
        { id: 'achievements' as const, label: '🏆 Achievements' },
        { id: 'demo' as const, label: '🎯 Demo Script' },
    ];

    return (
        <div style={{
            padding: '20px',
            minHeight: '100vh',
            background: 'radial-gradient(ellipse at bottom, #0d1117 0%, #03040b 100%)',
            color: '#fff',
            fontFamily: "'Inter', -apple-system, sans-serif"
        }}>
            <div style={{ display: 'flex', gap: '8px', marginBottom: '20px', flexWrap: 'wrap' }}>
                {sections.map(s => (
                    <button key={s.id} onClick={() => setActiveSection(s.id)} style={{
                        background: activeSection === s.id ? 'rgba(235, 47, 150, 0.15)' : 'rgba(22, 27, 34, 0.6)',
                        border: `1px solid ${activeSection === s.id ? '#eb2f9644' : '#21262d'}`,
                        color: activeSection === s.id ? '#eb2f96' : '#8b949e',
                        padding: '10px 18px',
                        borderRadius: '10px',
                        cursor: 'pointer',
                        fontSize: '0.85rem',
                        fontWeight: 600,
                        transition: 'all 0.2s',
                    }}>
                        {s.label}
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
                {activeSection === 'profiler' && <AgentProfiler />}
                {activeSection === 'multilang' && <MultiLanguageDemo />}
                {activeSection === 'timeline' && <ThreatTimeline />}
                {activeSection === 'achievements' && <AchievementsPanel />}
                {activeSection === 'demo' && <LiveDemoScript />}
            </div>
        </div>
    );
}
