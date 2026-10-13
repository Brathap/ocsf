import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Search, 
  Terminal, 
  ShieldAlert, 
  Laptop, 
  Database, 
  Sun, 
  Moon, 
  X,
  FileCode,
  Zap
} from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectTab: (tab: 'soc' | 'mapper' | 'provenance' | 'binary') => void;
  onTriggerSimulate: () => void;
  onTriggerHostLogs: () => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onSelectTab,
  onTriggerSimulate,
  onTriggerHostLogs
}) => {
  const [query, setQuery] = useState('');
  const { theme, toggleTheme } = useTheme();

  // Close on Escape, focus input on open
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const actions = [
    {
      id: 'tab-soc',
      title: 'Navigate to SOC Operations',
      subtitle: 'Real-time telemetry stream, MITRE ATT&CK taxonomy & EPS velocity',
      icon: Terminal,
      category: 'Navigation',
      run: () => { onSelectTab('soc'); onClose(); }
    },
    {
      id: 'tab-mapper',
      title: 'Open AI Schema Studio',
      subtitle: 'Map arbitrary proprietary syslog into OCSF v1.1.0 using LLM',
      icon: FileCode,
      category: 'Navigation',
      run: () => { onSelectTab('mapper'); onClose(); }
    },
    {
      id: 'tab-provenance',
      title: 'Open Air-Gap Provenance Ledger',
      subtitle: 'RFC 6962 Merkle tree proofs, tamper audits & cryptographic signatures',
      icon: Database,
      category: 'Navigation',
      run: () => { onSelectTab('provenance'); onClose(); }
    },
    {
      id: 'tab-binary',
      title: 'Open Bit Sandbox & Compiler',
      subtitle: 'Inspect raw network bytes, hex encoding & zero-allocation deserializer',
      icon: Zap,
      category: 'Navigation',
      run: () => { onSelectTab('binary'); onClose(); }
    },
    {
      id: 'action-simulate',
      title: 'Trigger Attack Simulation (MITRE ATT&CK)',
      subtitle: 'Inject Cobalt Strike beaconing & credential dump telemetry stream',
      icon: ShieldAlert,
      category: 'Defense Simulation',
      run: () => { onTriggerSimulate(); onClose(); }
    },
    {
      id: 'action-host',
      title: 'Toggle Local Host Machine Telemetry',
      subtitle: 'Stream live kernel syslog from host machine (macOS / Linux)',
      icon: Laptop,
      category: 'Live Ingestion',
      run: () => { onTriggerHostLogs(); onClose(); }
    },
    {
      id: 'action-theme',
      title: `Switch Theme to ${theme === 'dark' ? 'Warm Nixtio Light' : 'Deep Obsidian Dark'}`,
      subtitle: 'Toggle global color palette and ambient background mesh',
      icon: theme === 'dark' ? Sun : Moon,
      category: 'Interface',
      run: () => { toggleTheme(); onClose(); }
    }
  ];

  const filtered = actions.filter(a => 
    a.title.toLowerCase().includes(query.toLowerCase()) || 
    a.subtitle.toLowerCase().includes(query.toLowerCase()) ||
    a.category.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4">
        {/* Backdrop */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="fixed inset-0 bg-stone-900/60 dark:bg-black/80 backdrop-blur-md"
        />

        {/* Modal Window */}
        <motion.div
          initial={{ opacity: 0, scale: 0.96, y: -10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.96, y: -10 }}
          transition={{ duration: 0.15 }}
          className="relative w-full max-w-2xl bg-white dark:bg-slate-900 border border-stone-200/90 dark:border-slate-800 rounded-3xl shadow-2xl overflow-hidden z-10"
        >
          {/* Search Header */}
          <div className="p-4 border-b border-stone-100 dark:border-slate-800 flex items-center gap-3">
            <Search className="w-5 h-5 text-stone-400 dark:text-slate-500 shrink-0" />
            <input
              type="text"
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Type a command, navigate, or run defense audit... (Esc to close)"
              className="w-full bg-transparent text-sm sm:text-base text-stone-900 dark:text-white placeholder-stone-400 dark:placeholder-slate-500 outline-none font-sans"
            />
            <button
              onClick={onClose}
              className="p-1.5 rounded-full hover:bg-stone-100 dark:hover:bg-slate-800 text-stone-400 hover:text-stone-700 dark:hover:text-white transition cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Results List */}
          <div className="max-h-96 overflow-y-auto p-2 space-y-1">
            {filtered.length === 0 ? (
              <div className="p-8 text-center text-xs font-mono text-stone-400 dark:text-slate-500">
                No commands matching "{query}"
              </div>
            ) : (
              filtered.map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    onClick={item.run}
                    className="w-full text-left p-3 rounded-2xl hover:bg-stone-100 dark:hover:bg-slate-800/80 flex items-start gap-3 transition cursor-pointer group"
                  >
                    <div className="p-2 rounded-xl bg-stone-100 dark:bg-slate-800 group-hover:bg-amber-100 dark:group-hover:bg-amber-950/60 text-stone-600 dark:text-slate-300 group-hover:text-amber-700 dark:group-hover:text-amber-400 transition-colors shrink-0">
                      <Icon className="w-4 h-4" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <span className="text-xs sm:text-sm font-bold text-stone-900 dark:text-white truncate">
                          {item.title}
                        </span>
                        <span className="text-[10px] font-mono uppercase tracking-wider text-stone-400 dark:text-slate-500">
                          {item.category}
                        </span>
                      </div>
                      <p className="text-xs text-stone-500 dark:text-slate-400 truncate mt-0.5">
                        {item.subtitle}
                      </p>
                    </div>
                  </button>
                );
              })
            )}
          </div>

          {/* Footer Ribbon */}
          <div className="p-3 bg-stone-50/80 dark:bg-slate-950/60 border-t border-stone-100 dark:border-slate-800 flex items-center justify-between text-[11px] font-mono text-stone-400 dark:text-slate-500">
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1">
                <kbd className="px-1.5 py-0.5 rounded bg-stone-200 dark:bg-slate-800 text-stone-700 dark:text-slate-300 text-[10px]">⌘</kbd>
                <kbd className="px-1.5 py-0.5 rounded bg-stone-200 dark:bg-slate-800 text-stone-700 dark:text-slate-300 text-[10px]">K</kbd>
                <span>to open</span>
              </span>
              <span className="flex items-center gap-1">
                <kbd className="px-1.5 py-0.5 rounded bg-stone-200 dark:bg-slate-800 text-stone-700 dark:text-slate-300 text-[10px]">esc</kbd>
                <span>to close</span>
              </span>
            </div>
            <span className="text-amber-600 dark:text-amber-400 font-semibold">
              ULPF Air-Gap Core Active
            </span>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
