import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

interface KnowledgeDoc {
  id: string;
  title: String;
  content: string;
  tags: string[];
}

export default function KnowledgePanel() {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<KnowledgeDoc[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  // Listen for global events that trigger a contextual knowledge query
  useEffect(() => {
    const unlisten = listen<{ query: string }>("open-knowledge-panel", (e) => {
      setQuery(e.payload.query);
      setIsOpen(true);
      performQuery(e.payload.query);
    });
    return () => {
      unlisten.then(f => f());
    };
  }, []);

  const performQuery = async (searchQuery: string) => {
    if (!searchQuery.trim()) return;
    setIsLoading(true);
    try {
      const docs: KnowledgeDoc[] = await invoke("engine_query_knowledge_base", { query: searchQuery });
      setResults(docs);
    } catch (e) {
      console.error("Knowledge base query failed:", e);
      setResults([]);
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="knowledge-panel-overlay">
      <div className="knowledge-panel">
        <div className="kp-header">
          <div className="kp-title">
            <span className="icon">📚</span> Swarm Knowledge Base
          </div>
          <button className="kp-close" onClick={() => setIsOpen(false)}>×</button>
        </div>

        <div className="kp-search-bar">
          <input 
            type="text" 
            value={query} 
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && performQuery(query)}
            placeholder="Search CVEs, standards, or graph concepts..."
          />
          <button onClick={() => performQuery(query)}>Search</button>
        </div>

        <div className="kp-content">
          {isLoading ? (
            <div className="kp-loading">Querying local embeddings...</div>
          ) : results.length === 0 ? (
            <div className="kp-empty">No documentation found for this context.</div>
          ) : (
            <div className="kp-results">
              {results.map(doc => (
                <div key={doc.id} className="kp-doc-card">
                  <h4>{doc.title}</h4>
                  <div className="kp-tags">
                    {doc.tags.map(tag => (
                      <span key={tag} className="kp-tag">#{tag}</span>
                    ))}
                  </div>
                  <p>{doc.content}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <style>{`
        .knowledge-panel-overlay {
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          pointer-events: none;
          display: flex;
          justify-content: flex-end;
          z-index: 1050;
        }

        .knowledge-panel {
          pointer-events: auto;
          width: 450px;
          height: 100%;
          background: #0d1117;
          border-left: 1px solid #30363d;
          display: flex;
          flex-direction: column;
          box-shadow: -8px 0 24px rgba(0,0,0,0.5);
          animation: slideInRight 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        }

        @keyframes slideInRight {
          from { transform: translateX(100%); }
          to { transform: translateX(0); }
        }

        .kp-header {
          padding: 16px 20px;
          border-bottom: 1px solid #30363d;
          display: flex;
          align-items: center;
          justify-content: space-between;
          background: #161b22;
        }

        .kp-title {
          font-size: 1.1rem;
          font-weight: 600;
          color: #e6edf3;
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .kp-close {
          background: none;
          border: none;
          color: #8b949e;
          font-size: 24px;
          cursor: pointer;
          line-height: 1;
        }
        .kp-close:hover { color: #f85149; }

        .kp-search-bar {
          padding: 16px 20px;
          border-bottom: 1px solid #30363d;
          display: flex;
          gap: 10px;
          background: #0d1117;
        }
        .kp-search-bar input {
          flex: 1;
          background: #010409;
          border: 1px solid #30363d;
          padding: 10px 14px;
          border-radius: 6px;
          color: #c9d1d9;
          font-size: 0.95rem;
          outline: none;
        }
        .kp-search-bar input:focus { border-color: #58a6ff; }
        .kp-search-bar button {
          background: #238636;
          color: #fff;
          border: none;
          padding: 0 16px;
          border-radius: 6px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s;
        }
        .kp-search-bar button:hover { background: #2ea043; }

        .kp-content {
          flex: 1;
          overflow-y: auto;
          padding: 20px;
        }

        .kp-loading, .kp-empty {
          color: #8b949e;
          text-align: center;
          margin-top: 40px;
          font-size: 1rem;
        }

        .kp-results {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        .kp-doc-card {
          background: #161b22;
          border: 1px solid #30363d;
          border-radius: 8px;
          padding: 16px;
        }

        .kp-doc-card h4 {
          margin: 0 0 10px 0;
          color: #58a6ff;
          font-size: 1.1rem;
        }

        .kp-tags {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
          margin-bottom: 12px;
        }

        .kp-tag {
          background: rgba(88, 166, 255, 0.15);
          color: #79c0ff;
          padding: 2px 8px;
          border-radius: 12px;
          font-size: 0.75rem;
          font-weight: 600;
        }

        .kp-doc-card p {
          margin: 0;
          color: #c9d1d9;
          font-size: 0.95rem;
          line-height: 1.6;
        }
      `}</style>
    </div>
  );
}
