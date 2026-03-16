import { useState, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

interface ChatMessage {
  id: string;
  sender: 'user' | 'agent';
  agentName?: string;
  text: string;
  timestamp: Date;
}

export default function SwarmChat() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([{
    id: 'welcome',
    sender: 'agent',
    agentName: 'Swarm Orchestrator',
    text: "Hello. I am the central orchestrator for the AI DevSecOps Swarm. How can we help you secure this codebase today?",
    timestamp: new Date()
  }]);
  const [inputValue, setInputValue] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isOpen]);

  useEffect(() => {
    const unlisten = listen<{agent: string, message: string}>("swarm-chat-reply", (event) => {
      setMessages(prev => [...prev, {
        id: Math.random().toString(36).substring(7),
        sender: 'agent',
        agentName: event.payload.agent,
        text: event.payload.message,
        timestamp: new Date()
      }]);
    });

    return () => {
      unlisten.then(f => f());
    };
  }, []);

  const handleSend = async () => {
    if (!inputValue.trim()) return;

    const userMsg: ChatMessage = {
      id: Math.random().toString(36).substring(7),
      sender: 'user',
      text: inputValue,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMsg]);
    setInputValue("");

    try {
      await invoke("engine_chat_with_swarm", { message: userMsg.text });
    } catch (e) {
      console.error("Failed to send message to swarm:", e);
      setMessages(prev => [...prev, {
         id: Math.random().toString(),
         sender: 'agent',
         agentName: 'System Error',
         text: `Communication failure: ${e}`,
         timestamp: new Date()
      }]);
    }
  };

  if (!isOpen) {
    return (
      <button 
        className="swarm-chat-toggle"
        onClick={() => setIsOpen(true)}
      >
        💬 Chat with Swarm
      </button>
    );
  }

  return (
    <div className="swarm-chat-window">
      <div className="chat-header">
        <div className="chat-title">
           <span className="icon">🧠</span> AI Swarm Interface
        </div>
        <button className="chat-close" onClick={() => setIsOpen(false)}>×</button>
      </div>
      
      <div className="chat-messages">
        {messages.map(msg => (
          <div key={msg.id} className={`chat-bubble-wrapper ${msg.sender}`}>
             {msg.sender === 'agent' && (
                <div className="agent-name">{msg.agentName}</div>
             )}
            <div className={`chat-bubble ${msg.sender}`}>
              {msg.text}
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      <div className="chat-input-area">
        <input 
          type="text" 
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSend()}
          placeholder="Ask the swarm to explain a vulnerability..."
        />
        <button onClick={handleSend} disabled={!inputValue.trim()}>Send</button>
      </div>

      <style>{`
        .swarm-chat-toggle {
          position: fixed;
          bottom: 24px;
          right: 24px;
          background: linear-gradient(135deg, #177ddc 0%, #0958d9 100%);
          color: white;
          border: none;
          padding: 12px 20px;
          border-radius: 24px;
          font-size: 1rem;
          font-weight: 600;
          cursor: pointer;
          box-shadow: 0 4px 12px rgba(9, 88, 217, 0.4);
          z-index: 1000;
          transition: transform 0.2s, box-shadow 0.2s;
        }
        .swarm-chat-toggle:hover {
          transform: translateY(-2px);
          box-shadow: 0 6px 16px rgba(9, 88, 217, 0.6);
        }

        .swarm-chat-window {
          position: fixed;
          bottom: 24px;
          right: 24px;
          width: 380px;
          height: 550px;
          background: #0d1117;
          border: 1px solid #30363d;
          border-radius: 12px;
          display: flex;
          flex-direction: column;
          box-shadow: 0 12px 28px rgba(0,0,0,0.6);
          z-index: 1000;
          overflow: hidden;
        }

        .chat-header {
          background: #161b22;
          padding: 12px 16px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          border-bottom: 1px solid #30363d;
        }
        .chat-title {
          font-weight: 600;
          color: #e6edf3;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .chat-close {
          background: transparent;
          border: none;
          color: #8b949e;
          font-size: 1.5rem;
          cursor: pointer;
          line-height: 1;
        }
        .chat-close:hover {
          color: #f85149;
        }

        .chat-messages {
          flex: 1;
          overflow-y: auto;
          padding: 16px;
          display: flex;
          flex-direction: column;
          gap: 12px;
        }
        .chat-bubble-wrapper {
          display: flex;
          flex-direction: column;
          max-width: 85%;
        }
        .chat-bubble-wrapper.user {
          align-self: flex-end;
          align-items: flex-end;
        }
        .chat-bubble-wrapper.agent {
          align-self: flex-start;
          align-items: flex-start;
        }

        .agent-name {
          font-size: 0.75rem;
          color: #8b949e;
          margin-bottom: 4px;
          margin-left: 4px;
          font-weight: 600;
        }

        .chat-bubble {
          padding: 10px 14px;
          border-radius: 12px;
          font-size: 0.9rem;
          line-height: 1.4;
          word-wrap: break-word;
        }
        .chat-bubble.user {
          background: #1f6feb;
          color: white;
          border-bottom-right-radius: 2px;
        }
        .chat-bubble.agent {
          background: #21262d;
          color: #c9d1d9;
          border: 1px solid #30363d;
          border-bottom-left-radius: 2px;
        }

        .chat-input-area {
          padding: 12px;
          background: #161b22;
          border-top: 1px solid #30363d;
          display: flex;
          gap: 8px;
        }
        .chat-input-area input {
          flex: 1;
          background: #0d1117;
          border: 1px solid #30363d;
          color: #e6edf3;
          padding: 8px 12px;
          border-radius: 6px;
          font-size: 0.9rem;
          outline: none;
        }
        .chat-input-area input:focus {
          border-color: #58a6ff;
        }
        .chat-input-area button {
          background: #238636;
          color: white;
          border: none;
          padding: 0 16px;
          border-radius: 6px;
          cursor: pointer;
          font-weight: 600;
          transition: background 0.2s;
        }
        .chat-input-area button:hover:not(:disabled) {
          background: #2ea043;
        }
        .chat-input-area button:disabled {
          background: #21262d;
          color: #8b949e;
          cursor: not-allowed;
        }
      `}</style>
    </div>
  );
}
