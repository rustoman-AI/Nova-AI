import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

export default function VectorRagPanel() {
  const [query, setQuery] = useState('');
  const [limit, setLimit] = useState(5);
  const [isSearching, setIsSearching] = useState(false);
  const [results, setResults] = useState<any[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSearch = async () => {
    if (!query) return;

    try {
      setIsSearching(true);
      setErrorMsg(null);
      
      const res: any[] = await invoke('engine_vector_search', {
        query,
        limit
      });
      
      setResults(res);
    } catch (e: any) {
      setErrorMsg(e.toString());
      setResults([]);
    } finally {
      setIsSearching(false);
    }
  };

  return (
    <div className="settings-panel">
      <div className="settings-header">
        <h2>🧠 Vector RAG & Cortex Memory</h2>
        <p>Perform semantic cosine-similarity searches over the codebase using embedded AST snippets. Unlike traditional regex, this engine understands context and vulnerability semantics.</p>
      </div>

      <div className="settings-content">
        <div className="settings-section">
          <h3>Semantic Search</h3>
          
          <div className="mcp-server-form" style={{ paddingBottom: '1rem' }}>
            <div className="form-group-row" style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end' }}>
              <div className="form-group" style={{ flex: 1 }}>
                <label>Natural Language Query</label>
                <input 
                  type="text" 
                  value={query} 
                  onChange={(e) => setQuery(e.target.value)} 
                  onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                  placeholder="e.g. 'Where do we parse user passwords?'"
                  className="config-input"
                />
              </div>
              <div className="form-group" style={{ width: '120px' }}>
                <label>Max Results ({limit})</label>
                <input 
                  type="range" 
                  min={1} 
                  max={20} 
                  value={limit} 
                  onChange={(e) => setLimit(parseInt(e.target.value))} 
                  className="config-input"
                />
              </div>
              <button 
                className="save-btn" 
                onClick={handleSearch}
                disabled={isSearching || !query}
              >
                {isSearching ? <span className="spinner">↻</span> : 'Search'}
              </button>
            </div>
            {errorMsg && <div className="error-message" style={{ color: '#ff6b6b', marginTop: '0.5rem' }}>{errorMsg}</div>}
          </div>
        </div>

        <div className="settings-section" style={{ marginTop: '1rem' }}>
          <h3>Search Results</h3>
          <div className="rag-results-container">
            {results.length === 0 && !isSearching && (
              <div style={{ color: '#8b949e', fontStyle: 'italic', padding: '1rem 0' }}>
                No semantic matches found.
              </div>
            )}
            
            {results.map((result, idx) => (
              <div key={idx} style={{
                background: '#0d1117',
                border: '1px solid #30363d',
                borderRadius: '6px',
                padding: '1rem',
                marginBottom: '1rem',
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between'
              }}>
                <div>
                  <h4 style={{ margin: '0 0 0.5rem 0', color: '#58a6ff', fontFamily: 'monospace' }}>
                    📄 {result.id}
                  </h4>
                  <p style={{ margin: 0, color: '#c9d1d9', fontSize: '0.9rem' }}>
                    Semantic Cosine Score: <strong style={{ color: '#3fb950' }}>{((result.vector_score || 0) * 100).toFixed(1)}%</strong>
                  </p>
                  <p style={{ margin: '0.2rem 0 0 0', color: '#c9d1d9', fontSize: '0.9rem' }}>
                    Keyword BM25 Score: <strong style={{ color: '#a371f7' }}>{((result.keyword_score || 0) * 100).toFixed(1)}%</strong>
                  </p>
                </div>
                
                <div style={{ 
                  background: 'rgba(56, 139, 253, 0.1)', 
                  padding: '8px 12px', 
                  borderRadius: '20px',
                  color: '#58a6ff',
                  fontWeight: 'bold'
                }}>
                  {((result.final_score || 0) * 100).toFixed(0)}% Match
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
