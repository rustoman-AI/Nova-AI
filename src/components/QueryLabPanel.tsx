import React, { useState } from 'react';
import { QueryEngineAPI } from './QueryEngineApi';

interface QueryLabPanelProps {
    rootDir: string;
    sbomPath: string;
    onPathsFound: (paths: string[][]) => void;
}

export const QueryLabPanel: React.FC<QueryLabPanelProps> = ({ rootDir, sbomPath, onPathsFound }) => {
    const [query, setQuery] = useState('MATCH (api:EntryPoint {protocol: "http"})\n-[CALLS*1..5]-> (func:ASTNode)\n-[USES]-> (comp:Component {license: "GPL-3.0"})\nRETURN path');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleRunQuery = async () => {
        setLoading(true);
        setError(null);
        try {
            const results = await QueryEngineAPI.executeSecqlQuery(query, rootDir, sbomPath);
            const rawPaths = results.map(r => r.nodes);
            onPathsFound(rawPaths);
        } catch (e: any) {
            setError(e.toString());
            onPathsFound([]);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{
            position: 'absolute',
            bottom: 20,
            left: '50%',
            transform: 'translateX(-50%)',
            background: '#0a0a14FA',
            border: '1px solid #3366ff44',
            borderRadius: 8,
            padding: 16,
            width: 600,
            boxShadow: '0 8px 32px #000000CC',
            backdropFilter: 'blur(10px)',
            zIndex: 1000,
        }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ color: '#fff', fontWeight: 600, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ color: '#3366ff' }}>⚡</span> SecQL Query Lab
                </span>
                <span style={{ fontSize: 10, color: '#666' }}>DARPA-Level Inference</span>
            </div>

            <textarea
                value={query}
                onChange={e => setQuery(e.target.value)}
                style={{
                    width: '100%',
                    height: 80,
                    background: '#000',
                    border: '1px solid #333',
                    borderRadius: 4,
                    color: '#00ffcc',
                    fontFamily: 'monospace',
                    fontSize: 12,
                    padding: 8,
                    resize: 'none',
                    outline: 'none'
                }}
            />

            {error && (
                <div style={{ marginTop: 8, color: '#ff4d4f', fontSize: 11, background: '#ff4d4f22', padding: 6, borderRadius: 4 }}>
                    {error}
                </div>
            )}

            <div style={{ marginTop: 12, display: 'flex', justifyContent: 'flex-end' }}>
                <button
                    onClick={handleRunQuery}
                    disabled={loading}
                    style={{
                        background: loading ? '#333' : '#3366ff',
                        color: '#fff',
                        border: 'none',
                        borderRadius: 4,
                        padding: '6px 16px',
                        fontSize: 12,
                        fontWeight: 600,
                        cursor: loading ? 'not-allowed' : 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 6
                    }}
                >
                    {loading ? 'Executing...' : 'Run Query 🚀'}
                </button>
            </div>
        </div>
    );
};
