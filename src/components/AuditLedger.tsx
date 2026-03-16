import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface AuditEvent {
  event_type: string;
  timestamp: string;
  actor: {
    agent_id: string;
    subsystem: string | null;
    process_id: string | null;
  };
  action: {
    action_type: string;
    target: string;
    requires_approval: boolean;
    is_sandboxed: boolean;
  };
  result: {
    success: boolean;
    exit_code: number | null;
    duration_ms: number;
    error_msg: string | null;
  };
  security: {
    sandbox_breach_detected: boolean;
    policy_violation: boolean;
    data_leak_prevented: boolean;
    estop_triggered: boolean;
  };
  hash: string;
  prev_hash: string;
  signature: string;
}

const AuditLedger: React.FC = () => {
  const [logs, setLogs] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchLogs = async () => {
    try {
      const data = await invoke<AuditEvent[]>("engine_get_audit_logs");
      setLogs(data);
    } catch (e) {
      console.error("Failed to load audit logs:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="bg-[#1e1e1e] text-[#d4d4d4] p-4 flex flex-col h-full font-mono text-sm">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <span className="text-emerald-500">📜</span> Cryptographic Audit Ledger
        </h2>
        <button
          onClick={fetchLogs}
          className="px-3 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded shadow"
        >
          Refresh Logs
        </button>
      </div>

      <div className="flex-1 overflow-y-auto border border-[#3c3c3c] rounded bg-[#151515]">
        {loading ? (
          <div className="p-4 text-center text-gray-400">Loading audit trail...</div>
        ) : logs.length === 0 ? (
          <div className="p-4 text-center text-gray-400">No cryptographic audit logs found.</div>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead className="bg-[#2d2d2d] sticky top-0 z-10">
              <tr>
                <th className="p-2 border-b border-[#3c3c3c] text-gray-300">Timestamp</th>
                <th className="p-2 border-b border-[#3c3c3c] text-gray-300">Actor</th>
                <th className="p-2 border-b border-[#3c3c3c] text-gray-300">Action Target</th>
                <th className="p-2 border-b border-[#3c3c3c] text-gray-300">Status</th>
                <th className="p-2 border-b border-[#3c3c3c] text-gray-300">Hash (SHA-256)</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log, i) => (
                <tr key={i} className="hover:bg-[#252526] border-b border-[#2d2d2d] cursor-pointer group">
                  <td className="p-2 whitespace-nowrap text-gray-400">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="p-2 font-semibold text-blue-400">
                    {log.actor.agent_id}
                  </td>
                  <td className="p-2 text-yellow-300 max-w-xs truncate">
                    {log.action.target}
                  </td>
                  <td className="p-2">
                    {log.result.success ? (
                      <span className="px-2 py-0.5 bg-emerald-900 text-emerald-300 rounded text-xs border border-emerald-700">ALLOWED</span>
                    ) : (
                      <span className="px-2 py-0.5 bg-red-900 text-red-300 rounded text-xs border border-red-700">BLOCKED</span>
                    )}
                  </td>
                  <td className="p-2 text-gray-500 font-mono text-xs max-w-[150px] truncate" title={log.hash}>
                    {log.hash.substring(0, 16)}...
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default AuditLedger;
