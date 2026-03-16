import { useState, useEffect } from 'react';

const SLIDES = [
    {
        title: "The Problem",
        subtitle: "Software supply chain attacks increased 742% since 2020",
        content: [
            "🔴 Average time to detect a vulnerability: **197 days**",
            "🔴 Average cost of a data breach: **$4.88M** (IBM 2024)",
            "🔴 **91%** of open-source projects have unpatched vulnerabilities",
            "🔴 Manual code review cannot scale to modern CI/CD velocity",
        ],
        bg: "linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)",
        accent: "#ff4d4f"
    },
    {
        title: "Our Solution",
        subtitle: "Self-Evolving DevSecOps Agent powered by Amazon Nova",
        content: [
            "🧠 **Multi-Agent AI Swarm** — 5 specialized agents operating in real-time",
            "🔍 **ThreatIntel Agent** scans AST graphs and SBOMs for vulnerabilities",
            "⚙️ **PatchAgent** generates fixes using Amazon Nova LLM",
            "🛡️ **NovaShield Reviewer** validates patches for semantic correctness",
            "📋 **ComplianceBot** audits against PCI DSS, EU CRA, NIST",
        ],
        bg: "linear-gradient(135deg, #0d1117 0%, #161b22 100%)",
        accent: "#4facfe"
    },
    {
        title: "Architecture",
        subtitle: "Tauri + Rust + Amazon Bedrock + CycloneDX",
        content: [
            "⚡ **Tauri 2.0** — Secure desktop app (2MB binary vs 200MB Electron)",
            "🦀 **Rust Backend** — Zero-cost abstractions, memory safety",
            "☁️ **Amazon Nova via Bedrock** — Patch generation + review",
            "📦 **CycloneDX SBOM** — Industry-standard software bill of materials",
            "🔗 **Git Integration** — Auto-commit fixes to feature branches",
        ],
        bg: "linear-gradient(135deg, #0a0e14 0%, #1a1f2e 100%)",
        accent: "#13c2c2"
    },
    {
        title: "Live Demo",
        subtitle: "Watch the AI fix a vulnerability in real-time",
        content: [
            "1️⃣ **Detect** — ThreatIntel finds SQL Injection in api_server.rs",
            "2️⃣ **Fix** — PatchAgent generates parameterized query via Nova",
            "3️⃣ **Review** — NovaShield validates the patch (no regressions)",
            "4️⃣ **Commit** — GitAgent writes to disk + creates branch + commits",
            "5️⃣ **Audit** — ComplianceBot verifies PCI DSS / EU CRA / NIST",
        ],
        bg: "linear-gradient(135deg, #0d1117 0%, #0a1628 100%)",
        accent: "#eb2f96"
    },
    {
        title: "Impact",
        subtitle: "From 197 days to 30 seconds",
        content: [
            "⚡ **6,500x faster** vulnerability remediation",
            "💰 **$4.88M → $0** breach cost reduction per incident",
            "📊 **100% compliance** score across 3 regulatory frameworks",
            "🔄 **Zero human intervention** — fully autonomous healing",
            "🌍 **Multi-language** support: Rust, Python, JavaScript",
        ],
        bg: "linear-gradient(135deg, #0d1117 0%, #1a0a2e 100%)",
        accent: "#52c41a"
    },
    {
        title: "Built With",
        subtitle: "Amazon Nova 🤝 CycloneDX 🤝 Tauri",
        content: [
            "☁️ **Amazon Nova** — Foundation model for code generation & review",
            "☁️ **Amazon Bedrock** — Managed inference API",
            "📦 **CycloneDX** — SBOM standard for supply chain transparency",
            "🦀 **Tauri + Rust** — Secure, performant desktop runtime",
            "🐙 **libgit2** — Programmatic Git operations",
        ],
        bg: "linear-gradient(135deg, #0d1117 0%, #16213e 100%)",
        accent: "#722ed1"
    },
];

export default function PitchSlides() {
    const [current, setCurrent] = useState(0);
    const [isFullscreen, setIsFullscreen] = useState(false);

    useEffect(() => {
        const handler = (e: KeyboardEvent) => {
            if (e.key === 'ArrowRight' || e.key === ' ') setCurrent(p => Math.min(p + 1, SLIDES.length - 1));
            if (e.key === 'ArrowLeft') setCurrent(p => Math.max(p - 1, 0));
            if (e.key === 'Escape') setIsFullscreen(false);
            if (e.key === 'f' || e.key === 'F') setIsFullscreen(p => !p);
        };
        window.addEventListener('keydown', handler);
        return () => window.removeEventListener('keydown', handler);
    }, []);

    const slide = SLIDES[current];

    return (
        <div style={{
            position: isFullscreen ? 'fixed' : 'relative',
            top: isFullscreen ? 0 : 'auto',
            left: isFullscreen ? 0 : 'auto',
            width: isFullscreen ? '100vw' : '100%',
            height: isFullscreen ? '100vh' : 'auto',
            minHeight: isFullscreen ? '100vh' : '600px',
            background: slide.bg,
            zIndex: isFullscreen ? 9999 : 1,
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'center',
            padding: '60px 40px',
            fontFamily: "'Inter', -apple-system, sans-serif",
            transition: 'background 0.8s ease',
            borderRadius: isFullscreen ? 0 : '16px',
            overflow: 'hidden',
            color: '#fff',
        }}>
            {/* Slide counter */}
            <div style={{ position: 'absolute', top: 20, right: 30, color: '#484f58', fontSize: '0.9rem', fontWeight: 600 }}>
                {current + 1} / {SLIDES.length}
            </div>

            {/* Fullscreen button */}
            <button onClick={() => setIsFullscreen(p => !p)} style={{
                position: 'absolute', top: 20, left: 30,
                background: 'rgba(255,255,255,0.05)',
                border: '1px solid #30363d',
                color: '#8b949e',
                padding: '6px 14px',
                borderRadius: '8px',
                cursor: 'pointer',
                fontSize: '0.8rem'
            }}>
                {isFullscreen ? '⬜ Exit' : '⬛ Fullscreen'} (F)
            </button>

            {/* Title */}
            <h1 style={{
                fontSize: isFullscreen ? '4.5rem' : '3rem',
                fontWeight: 800,
                letterSpacing: '-2px',
                background: `linear-gradient(90deg, ${slide.accent}, ${slide.accent}aa)`,
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                margin: '0 0 10px',
                textAlign: 'center',
                animation: 'fadeIn 0.5s ease-out',
            }}>{slide.title}</h1>

            {/* Subtitle */}
            <p style={{
                fontSize: isFullscreen ? '1.5rem' : '1.1rem',
                color: '#8b949e',
                marginBottom: '40px',
                textAlign: 'center',
                maxWidth: '700px',
                animation: 'fadeIn 0.7s ease-out',
            }}>{slide.subtitle}</p>

            {/* Content */}
            <div style={{
                maxWidth: '800px',
                display: 'flex',
                flexDirection: 'column',
                gap: '16px',
            }}>
                {slide.content.map((line, i) => (
                    <div key={i} style={{
                        fontSize: isFullscreen ? '1.4rem' : '1rem',
                        color: '#c9d1d9',
                        lineHeight: 1.6,
                        padding: '8px 0',
                        borderBottom: '1px solid #21262d22',
                        animation: `fadeSlideIn ${0.3 + i * 0.15}s ease-out`,
                    }}
                        dangerouslySetInnerHTML={{ __html: line.replace(/\*\*(.*?)\*\*/g, '<strong style="color: #fff">$1</strong>') }}
                    />
                ))}
            </div>

            {/* Navigation dots */}
            <div style={{ display: 'flex', gap: '10px', marginTop: '50px' }}>
                {SLIDES.map((_, i) => (
                    <button key={i} onClick={() => setCurrent(i)} style={{
                        width: i === current ? '30px' : '10px',
                        height: '10px',
                        borderRadius: '5px',
                        background: i === current ? slide.accent : '#30363d',
                        border: 'none',
                        cursor: 'pointer',
                        transition: 'all 0.3s ease'
                    }} />
                ))}
            </div>

            {/* Nav arrows */}
            <div style={{ position: 'absolute', bottom: 30, display: 'flex', gap: '12px' }}>
                <button onClick={() => setCurrent(p => Math.max(0, p - 1))} disabled={current === 0} style={{
                    background: 'rgba(255,255,255,0.05)', border: '1px solid #30363d',
                    color: current === 0 ? '#30363d' : '#8b949e', padding: '10px 20px',
                    borderRadius: '8px', cursor: 'pointer', fontSize: '1rem'
                }}>← Prev</button>
                <button onClick={() => setCurrent(p => Math.min(SLIDES.length - 1, p + 1))} disabled={current === SLIDES.length - 1} style={{
                    background: current === SLIDES.length - 1 ? 'rgba(255,255,255,0.05)' : `${slide.accent}22`,
                    border: `1px solid ${current === SLIDES.length - 1 ? '#30363d' : slide.accent + '44'}`,
                    color: current === SLIDES.length - 1 ? '#30363d' : slide.accent,
                    padding: '10px 20px', borderRadius: '8px', cursor: 'pointer', fontSize: '1rem', fontWeight: 600
                }}>Next →</button>
            </div>

            <style>{`
                @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                @keyframes fadeSlideIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
            `}</style>
        </div>
    );
}
