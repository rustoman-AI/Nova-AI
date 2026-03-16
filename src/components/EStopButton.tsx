import React, { useState } from 'react';
import { useEstop } from './EstopProvider';
import { AlertOctagon, RefreshCcw } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export const EStopButton: React.FC = () => {
  const { isEngaged, engage, resume } = useEstop();
  const [loading, setLoading] = useState(false);

  const handleToggle = async () => {
    setLoading(true);
    if (isEngaged) {
      await resume();
    } else {
      await engage();
    }
    setLoading(false);
  };

  return (
    <div className="relative group">
      <button
        onClick={handleToggle}
        disabled={loading}
        className={`flex items-center gap-2 px-4 py-2 rounded-md font-bold text-sm transition-all duration-300 relative overflow-hidden z-10 ${
          isEngaged 
            ? 'bg-red-500 hover:bg-red-600 text-white shadow-[0_0_15px_rgba(239,68,68,0.7)] animate-pulse' 
            : 'bg-zinc-800 hover:bg-zinc-700 text-red-500 border border-red-900/50 hover:border-red-500/50'
        }`}
      >
        <AnimatePresence mode="wait">
          {isEngaged ? (
            <motion.div
              key="resume"
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.8 }}
              className="flex items-center gap-2"
            >
              <RefreshCcw size={16} className={loading ? 'animate-spin' : ''} />
              RESUME OPS
            </motion.div>
          ) : (
            <motion.div
              key="estop"
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.8 }}
              className="flex items-center gap-2"
            >
              <AlertOctagon size={16} className={loading ? 'animate-spin' : ''} />
              E-STOP
            </motion.div>
          )}
        </AnimatePresence>
      </button>

      {/* Warning glow effect */}
      <div 
        className={`absolute inset-0 rounded-md z-0 pointer-events-none transition-opacity duration-300 ${isEngaged ? 'opacity-100 shadow-[0_0_20px_4px_rgba(239,68,68,0.5)]' : 'opacity-0 glow-hover'}`}
        style={!isEngaged ? { boxShadow: '0 0 10px 1px rgba(239, 68, 68, 0.3)' } : {}}
      />
    </div>
  );
};
