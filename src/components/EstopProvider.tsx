import React, { createContext, useContext, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

export interface EstopState {
  kill_all: boolean;
  network_kill: boolean;
  blocked_domains: string[];
  frozen_tools: string[];
  updated_at?: string;
}

interface EstopContextType {
  status: EstopState;
  isEngaged: boolean;
  refreshStatus: () => Promise<void>;
  engage: () => Promise<void>;
  resume: () => Promise<void>;
}

const defaultState: EstopState = {
  kill_all: false,
  network_kill: false,
  blocked_domains: [],
  frozen_tools: [],
};

const EstopContext = createContext<EstopContextType | undefined>(undefined);

export const EstopProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [status, setStatus] = useState<EstopState>(defaultState);

  const isEngaged = status.kill_all || status.network_kill || status.blocked_domains.length > 0 || status.frozen_tools.length > 0;

  const refreshStatus = async () => {
    try {
      const result = await invoke<EstopState>('engine_estop_status');
      setStatus(result);
    } catch (e) {
      console.error('Failed to fetch estop status', e);
    }
  };

  const engage = async () => {
    try {
      const result = await invoke<EstopState>('engine_estop_engage');
      setStatus(result);
    } catch (e) {
      console.error('Failed to engage estop', e);
    }
  };

  const resume = async () => {
    try {
      const result = await invoke<EstopState>('engine_estop_resume');
      setStatus(result);
    } catch (e) {
      console.error('Failed to resume operations', e);
    }
  };

  useEffect(() => {
    refreshStatus();
    const interval = setInterval(refreshStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <EstopContext.Provider value={{ status, isEngaged, refreshStatus, engage, resume }}>
      {children}
    </EstopContext.Provider>
  );
};

export const useEstop = () => {
  const context = useContext(EstopContext);
  if (context === undefined) {
    throw new Error('useEstop must be used within an EstopProvider');
  }
  return context;
};
