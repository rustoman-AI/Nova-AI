import { useState } from 'react';

type DepNode = {
    name: string;
    version: string;
    risk: 'safe' | 'low' | 'medium' | 'critical';
    cve?: string;
    children?: DepNode[];
};

const TREE: DepNode = {
    name: 'cyclonedx-tauri-ui', version: '0.1.0', risk: 'safe',
    children: [
        { name: 'tauri', version: '2.0.0', risk: 'safe', children: [
            { name: 'tauri-runtime-wry', version: '2.0.0', risk: 'safe' },
            { name: 'tauri-utils', version: '2.0.0', risk: 'safe' },
            { name: 'tauri-plugin-opener', version: '2.0.0', risk: 'safe' },
        ]},
        { name: 'tokio', version: '1.37.0', risk: 'safe', children: [
            { name: 'mio', version: '0.8.11', risk: 'safe' },
            { name: 'bytes', version: '1.6.0', risk: 'safe' },
            { name: 'parking_lot', version: '0.12.2', risk: 'safe' },
        ]},
        { name: 'serde', version: '1.0.203', risk: 'safe', children: [
            { name: 'serde_derive', version: '1.0.203', risk: 'safe' },
        ]},
        { name: 'serde_json', version: '1.0.120', risk: 'safe' },
        { name: 'reqwest', version: '0.12.5', risk: 'low', children: [
            { name: 'hyper', version: '1.3.1', risk: 'safe' },
            { name: 'rustls', version: '0.23.10', risk: 'safe' },
            { name: 'h2', version: '0.4.5', risk: 'low', cve: 'RUSTSEC-2024-0332' },
        ]},
        { name: 'sqlx', version: '0.7.4', risk: 'safe', children: [
            { name: 'sqlx-core', version: '0.7.4', risk: 'safe' },
            { name: 'sqlx-sqlite', version: '0.7.4', risk: 'safe' },
        ]},
        { name: 'git2', version: '0.18.3', risk: 'safe', children: [
            { name: 'libgit2-sys', version: '0.16.2', risk: 'safe' },
        ]},
        { name: 'petgraph', version: '0.6.5', risk: 'safe' },
        { name: 'aws-sdk-bedrockruntime', version: '1.45.0', risk: 'safe', children: [
            { name: 'aws-config', version: '1.5.4', risk: 'safe' },
            { name: 'aws-smithy-runtime', version: '1.6.1', risk: 'safe' },
            { name: 'aws-sigv4', version: '1.2.2', risk: 'safe' },
        ]},
        { name: 'chrono', version: '0.4.38', risk: 'safe' },
        { name: 'uuid', version: '1.9.1', risk: 'safe' },
        { name: 'dotenvy', version: '0.15.7', risk: 'safe' },
    ]
};

const riskColor: Record<string, string> = {
    safe: '#52c41a', low: '#4facfe', medium: '#faad14', critical: '#ff4d4f'
};

function TreeNode({ node, depth = 0 }: { node: DepNode; depth?: number }) {
    const [expanded, setExpanded] = useState(depth < 1);
    const hasKids = node.children && node.children.length > 0;
    const color = riskColor[node.risk];

    return (
        <div style={{ marginLeft: depth * 20 }}>
            <div
                onClick={() => hasKids && setExpanded(!expanded)}
                style={{
                    display: 'flex', alignItems: 'center', gap: '8px',
                    padding: '4px 8px', borderRadius: '6px', cursor: hasKids ? 'pointer' : 'default',
                    background: node.cve ? `${color}11` : 'transparent',
                    border: node.cve ? `1px solid ${color}33` : '1px solid transparent',
                    marginBottom: '2px',
                    transition: 'background 0.15s',
                }}
            >
                {hasKids ? (
                    <span style={{ color: '#484f58', fontSize: '0.7rem', width: '14px', textAlign: 'center' }}>
                        {expanded ? '▼' : '▶'}
                    </span>
                ) : (
                    <span style={{ width: '14px', textAlign: 'center', color: '#21262d' }}>•</span>
                )}
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: color, flexShrink: 0 }} />
                <span style={{ fontSize: '0.85rem', color: '#c9d1d9', fontWeight: depth === 0 ? 700 : 400 }}>
                    {node.name}
                </span>
                <span style={{ fontSize: '0.75rem', color: '#484f58' }}>v{node.version}</span>
                {node.cve && (
                    <code style={{
                        fontSize: '0.65rem', background: `${color}22`, color,
                        padding: '1px 6px', borderRadius: '3px', fontWeight: 600
                    }}>{node.cve}</code>
                )}
            </div>
            {expanded && hasKids && node.children!.map(child => (
                <TreeNode key={child.name} node={child} depth={depth + 1} />
            ))}
        </div>
    );
}

export default function DependencyTreePanel() {
    const totalDeps = countDeps(TREE);
    const vulnDeps = countVulns(TREE);

    return (
        <div style={{
            padding: '20px',
            minHeight: '100vh',
            background: 'radial-gradient(ellipse at bottom, #0d1117 0%, #03040b 100%)',
            color: '#fff',
            fontFamily: "'Inter', -apple-system, sans-serif"
        }}>
            <h2 style={{ margin: '0 0 8px', fontSize: '1.3rem' }}>🌳 Dependency Tree</h2>
            <div style={{ display: 'flex', gap: '16px', marginBottom: '16px', fontSize: '0.8rem', color: '#8b949e' }}>
                <span>{totalDeps} dependencies</span>
                <span style={{ color: vulnDeps > 0 ? '#faad14' : '#52c41a' }}>
                    {vulnDeps} with advisories
                </span>
                <span><span style={{ color: '#52c41a' }}>●</span> safe</span>
                <span><span style={{ color: '#4facfe' }}>●</span> low</span>
                <span><span style={{ color: '#faad14' }}>●</span> medium</span>
                <span><span style={{ color: '#ff4d4f' }}>●</span> critical</span>
            </div>
            <div style={{
                background: 'rgba(22, 27, 34, 0.4)',
                border: '1px solid #30363d',
                borderRadius: '16px',
                padding: '20px',
                backdropFilter: 'blur(10px)',
                maxHeight: '600px',
                overflowY: 'auto'
            }}>
                <TreeNode node={TREE} />
            </div>
        </div>
    );
}

function countDeps(node: DepNode): number {
    let count = 1;
    if (node.children) node.children.forEach(c => count += countDeps(c));
    return count;
}
function countVulns(node: DepNode): number {
    let count = node.cve ? 1 : 0;
    if (node.children) node.children.forEach(c => count += countVulns(c));
    return count;
}
