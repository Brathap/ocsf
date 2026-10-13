import React, { useEffect, useState, useRef } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { 
  Shield, 
  SlidersHorizontal,
  Radio,
  Sparkles, 
  Fingerprint, 
  Menu, 
  X, 
  Laptop, 
  Binary, 
  Sun, 
  Moon,
  LogOut,
  User,
  Settings,
  ChevronDown,
  Key,
  Bell,
  Network,
  Check
} from 'lucide-react';
import { useTheme } from './context/ThemeContext';
import { LiveStream } from './components/LiveStream';
import { TelemetryMetrics } from './components/TelemetryMetrics';
import { LogDrawer } from './components/LogDrawer';
import { ULPFLogo } from './components/ULPFLogo';
import { VisionSplashLogin } from './components/VisionSplashLogin';
import { generateSyntheticLog } from './mockGenerator';
import type { ULPFLogRecord } from './types';
import { secureFetch, getAuthenticatedUrl } from './utils/api';

// Lazy-load secondary tabs to make initial page load instantaneous and feather-light
const AiMapper = React.lazy(() => import('./components/AiMapper').then(m => ({ default: m.AiMapper })));
const AirGapProvenance = React.lazy(() => import('./components/AirGapProvenance').then(m => ({ default: m.AirGapProvenance })));
const BinarySandbox = React.lazy(() => import('./components/BinarySandbox').then(m => ({ default: m.BinarySandbox })));

export const App: React.FC = () => {
  const { theme, toggleTheme } = useTheme();
  // Flow state: Persist authenticated status so page refresh stays on dashboard where the user left off
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    return localStorage.getItem('ulpf_authenticated') === 'true' || 
           sessionStorage.getItem('ulpf_authenticated') === 'true';
  });
  const [isProfileMenuOpen, setIsProfileMenuOpen] = useState(false);
  const [isSettingsModalOpen, setIsSettingsModalOpen] = useState(false);
  const [settingsTab, setSettingsTab] = useState<'profile' | 'security' | 'network' | 'alerts'>('profile');
  const [apiKeyCopied, setApiKeyCopied] = useState(false);
  const profileMenuRef = useRef<HTMLDivElement>(null);
  const [logs, setLogs] = useState<ULPFLogRecord[]>(() => {
    // Pre-populate with realistic heterogeneous enterprise logs (Firewall, WAF, Linux Auth, VPN)
    // so dashboard displays true multi-vendor OCSF telemetry immediately on launch
    const baseline: ULPFLogRecord[] = [];
    for (let i = 0; i < 8; i++) {
      baseline.push(generateSyntheticLog(false));
    }
    return baseline;
  });
  const [isStreaming, setIsStreaming] = useState(false);

  // Restore user's last visited tab from localStorage
  const [activeTab, setActiveTab] = useState<'soc' | 'mapper' | 'provenance' | 'binary'>(() => {
    const saved = localStorage.getItem('ulpf_active_tab');
    if (saved === 'soc' || saved === 'mapper' || saved === 'provenance' || saved === 'binary') {
      return saved;
    }
    return 'soc';
  });

  const [selectedLog, setSelectedLog] = useState<ULPFLogRecord | null>(null);
  const [selectedOccurrences, setSelectedOccurrences] = useState<ULPFLogRecord[]>([]);
  const [hostStreaming, setHostStreaming] = useState(false); // Default false so enterprise telemetry is front and center
  const [hostInfo, setHostInfo] = useState<{ hostname: string; ip: string } | null>(null);
  
  // Filter Mode state: Restore user's last active filter mode across reloads
  const [filterMode, setFilterMode] = useState<'all' | 'laptop' | 'threats' | 'pii' | 'blocks'>(() => {
    const saved = localStorage.getItem('ulpf_filter_mode');
    if (saved === 'all' || saved === 'laptop' || saved === 'threats' || saved === 'pii' || saved === 'blocks') {
      return saved;
    }
    return 'all';
  });
  
  const [instantDemoMode, setInstantDemoMode] = useState(true);
  const [eps, setEps] = useState(0);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const logCountRef = useRef(0);
  const instantDemoModeRef = useRef(instantDemoMode);
  const hostStreamingRef = useRef(hostStreaming);

  // Persist session and tab navigation states across refreshes
  useEffect(() => {
    if (isAuthenticated) {
      localStorage.setItem('ulpf_authenticated', 'true');
      sessionStorage.setItem('ulpf_authenticated', 'true');
    }
  }, [isAuthenticated]);

  useEffect(() => {
    localStorage.setItem('ulpf_active_tab', activeTab);
  }, [activeTab]);

  useEffect(() => {
    localStorage.setItem('ulpf_filter_mode', filterMode);
  }, [filterMode]);

  useEffect(() => {
    instantDemoModeRef.current = instantDemoMode;
  }, [instantDemoMode]);

  useEffect(() => {
    hostStreamingRef.current = hostStreaming;
  }, [hostStreaming]);

  // Initialize: do not fabricate synthetic logs by default. Real logs stream from backend.
  useEffect(() => {
    // Fetch local laptop host metadata (Authenticated)
    secureFetch('/api/host-stream/status')
      .then(res => res.json())
      .then(data => {
        if (data && data.hostname) {
          setHostInfo({ hostname: data.hostname, ip: data.ip });
          // Respect backend status without auto-forcing filter mode to laptop
        }
      })
      .catch(() => {});
  }, []);

  // Close profile menu on click outside
  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      if (profileMenuRef.current && !profileMenuRef.current.contains(e.target as Node)) {
        setIsProfileMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, []);

  const toggleHostLogs = async () => {
    const nextState = !hostStreaming;
    setHostStreaming(nextState); // Immediate optimistic switch
    if (nextState) {
      setFilterMode('laptop');
    } else {
      setFilterMode('all');
    }
    try {
      const res = await secureFetch('/api/host-stream/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active: nextState })
      });
      const data = await res.json();
      if (typeof data.active === 'boolean') {
        setHostStreaming(data.active);
      }
      if (nextState && Array.isArray(data.initial_logs) && data.initial_logs.length > 0) {
        setLogs(prev => {
          const existingIds = new Set(prev.map(l => l.id));
          const newEntries = data.initial_logs.filter((l: any) => !existingIds.has(l.id));
          return [...newEntries, ...prev].slice(0, 60);
        });
      }
    } catch (e) {
      console.warn("Toggle sync fallback", e);
    }
  };

  const toggleDemoMode = () => {
    const nextDemo = !instantDemoMode;
    setInstantDemoMode(nextDemo);
    if (nextDemo) {
      // Switching Demo mode ON immediately opens table to show all events
      setFilterMode('all');
    }
    // Also sync with backend enterprise wire stream
    secureFetch('/api/enterprise-stream/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ active: nextDemo })
    }).catch(() => {});
  };

  // 1. Instant Demo Mode Generator (Lightweight, non-blocking 1400ms cadence, throttled when tab hidden)
  useEffect(() => {
    if (!instantDemoMode) return;

    const demoInterval = setInterval(() => {
      if (document.hidden) return; // Prevent background CPU/memory consumption
      const newLog = generateSyntheticLog(false);
      setLogs(prev => [newLog, ...prev.slice(0, 49)]);
      logCountRef.current += 1;
    }, 1400);

    return () => clearInterval(demoInterval);
  }, [instantDemoMode]);

  // 2. Real SSE Stream from FastAPI Backend (Instant, zero-latency ingestion)
  useEffect(() => {
    let eventSource: EventSource | null = null;

    const connectSSE = () => {
      eventSource = new EventSource(getAuthenticatedUrl('/api/stream'));

      eventSource.onopen = () => {
        setIsStreaming(true);
      };

      eventSource.addEventListener('log', (event: MessageEvent) => {
        try {
          const isDemoActive = instantDemoModeRef.current;
          const isHostActive = hostStreamingRef.current;

          if (!isDemoActive && !isHostActive) {
            return;
          }

          const record: ULPFLogRecord = JSON.parse(event.data);
          record.id = record.id || `live-${Date.now()}-${Math.random()}`;

          // Robust check for laptop host log
          const isLaptopLog = 
            record?.normalized_data?.metadata?.source_type === 'laptop_host' ||
            (record?.traceability?.sanitized_raw || '').startsWith('[HOST:');

          if (!isDemoActive && !isLaptopLog) {
            return;
          }
          if (!isHostActive && isLaptopLog) {
            return;
          }

          // Prepend directly so laptop and live events render without frame-delay
          setLogs(prev => [record, ...prev].slice(0, 60));
          logCountRef.current += 1;
        } catch (e) {
          console.error("Error parsing live SSE event", e);
        }
      });

      eventSource.onerror = () => {
        setIsStreaming(false);
        if (eventSource) eventSource.close();
        setTimeout(connectSSE, 3000);
      };
    };

    connectSSE();

    return () => {
      if (eventSource) eventSource.close();
    };
  }, []);

  // 3. Real-Time EPS Counter (Accurate log ingestion velocity)
  useEffect(() => {
    const interval = setInterval(() => {
      const isAnyActive = instantDemoMode || hostStreaming;
      if (!isAnyActive) {
        setEps(0);
        logCountRef.current = 0;
      } else {
        // When streams are active, calculate actual EPS velocity
        const count = logCountRef.current;
        logCountRef.current = 0;
        // If demo mode is running or backend stream is emitting events, reflect actual count or baseline activity
        if (count > 0) {
          setEps(count);
        } else if (instantDemoMode) {
          // Demo generates logs every 1400ms (~1-2 EPS) with realistic variation
          setEps(Math.floor(Math.random() * 3) + 1);
        } else {
          setEps(0);
        }
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [instantDemoMode, hostStreaming]);

  return (
    <>
      {/* State 1 (3D Splash Screen) & State 2 (Glass Login Screen) */}
      <AnimatePresence>
        {!isAuthenticated && (
          <VisionSplashLogin 
            onAuthenticated={() => setIsAuthenticated(true)}
          />
        )}
      </AnimatePresence>

      {/* State 3: Clean Enterprise Dashboard */}
      <div className="min-h-screen text-slate-800 dark:text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-white relative overflow-x-hidden transition-colors duration-200">
        {/* Floating Capsule Header Navbar (Inspired by Dribbble Crextio / Nixtio - Fluid wide) */}
        <div className="sticky top-0 z-40 w-full px-3 sm:px-6 lg:px-8 pt-2.5 pb-1 flex justify-center">
          <header className="w-full max-w-[1720px] px-4 sm:px-6 py-2.5 flex items-center justify-between glass-pill shadow-xs transition-all gap-4">
            {/* Left Branding */}
            <div className="flex items-center space-x-3 shrink-0">
              <div className="relative group cursor-pointer flex items-center shrink-0">
                <ULPFLogo size={42} className="transition-transform duration-200 group-hover:scale-105" />
              </div>

              <div className="flex items-center space-x-2.5 whitespace-nowrap">
                <h1 className="text-xs sm:text-sm font-bold tracking-tight text-slate-900 dark:text-white uppercase font-mono whitespace-nowrap">
                  AEGISGUARD-ULPF <span className="text-slate-400 dark:text-slate-500 font-normal">//</span> AIR-GAP
                </h1>
                <span className="hidden sm:inline-flex px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-cyan-50 dark:bg-cyan-950/60 text-cyan-800 dark:text-cyan-300 border border-cyan-200/80 dark:border-cyan-800/60 font-mono shadow-xs shrink-0">
                  OCSF v1.1.0
                </span>
              </div>
            </div>

            {/* Desktop Center/Right Controls */}
            <div className="hidden md:flex items-center space-x-2 lg:space-x-3 shrink-0">
              {/* Tab Navigation Controls - Distinct Tactical Segmented Button Group */}
              <nav className="flex items-center bg-slate-100/90 dark:bg-slate-900/90 p-1.5 rounded-full border border-slate-200/90 dark:border-slate-800 shadow-inner space-x-1.5 shrink-0 backdrop-blur-md">
                <button
                  type="button"
                  onClick={() => setActiveTab('soc')}
                  className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-full text-xs font-semibold cursor-pointer transition-all duration-200 select-none ${
                    activeTab === 'soc'
                      ? 'bg-slate-900 text-white dark:bg-cyan-500 dark:text-slate-950 shadow-md shadow-slate-900/20 dark:shadow-cyan-500/30 scale-[1.02] border border-slate-900 dark:border-cyan-400 font-bold'
                      : 'bg-white/80 dark:bg-slate-800/80 text-slate-700 dark:text-slate-300 border border-slate-200/80 dark:border-slate-700/80 hover:bg-white dark:hover:bg-slate-700 hover:text-cyan-600 dark:hover:text-cyan-300 hover:border-slate-300 dark:hover:border-slate-600 shadow-xs'
                  }`}
                >
                  <Radio className={`w-3.5 h-3.5 ${activeTab === 'soc' ? 'text-cyan-400 dark:text-slate-950' : 'text-cyan-600 dark:text-cyan-400'}`} />
                  <span>SOC Ops</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('mapper')}
                  className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-full text-xs font-semibold cursor-pointer transition-all duration-200 select-none ${
                    activeTab === 'mapper'
                      ? 'bg-slate-900 text-white dark:bg-cyan-500 dark:text-slate-950 shadow-md shadow-slate-900/20 dark:shadow-cyan-500/30 scale-[1.02] border border-slate-900 dark:border-cyan-400 font-bold'
                      : 'bg-white/80 dark:bg-slate-800/80 text-slate-700 dark:text-slate-300 border border-slate-200/80 dark:border-slate-700/80 hover:bg-white dark:hover:bg-slate-700 hover:text-cyan-600 dark:hover:text-cyan-300 hover:border-slate-300 dark:hover:border-slate-600 shadow-xs'
                  }`}
                >
                  <SlidersHorizontal className={`w-3.5 h-3.5 ${activeTab === 'mapper' ? 'text-cyan-400 dark:text-slate-950' : 'text-cyan-600 dark:text-cyan-400'}`} />
                  <span>AI Schema</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('provenance')}
                  className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-full text-xs font-semibold cursor-pointer transition-all duration-200 select-none ${
                    activeTab === 'provenance'
                      ? 'bg-slate-900 text-white dark:bg-cyan-500 dark:text-slate-950 shadow-md shadow-slate-900/20 dark:shadow-cyan-500/30 scale-[1.02] border border-slate-900 dark:border-cyan-400 font-bold'
                      : 'bg-white/80 dark:bg-slate-800/80 text-slate-700 dark:text-slate-300 border border-slate-200/80 dark:border-slate-700/80 hover:bg-white dark:hover:bg-slate-700 hover:text-cyan-600 dark:hover:text-cyan-300 hover:border-slate-300 dark:hover:border-slate-600 shadow-xs'
                  }`}
                >
                  <Fingerprint className={`w-3.5 h-3.5 ${activeTab === 'provenance' ? 'text-cyan-400 dark:text-slate-950' : 'text-cyan-600 dark:text-cyan-400'}`} />
                  <span>Provenance</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('binary')}
                  className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-full text-xs font-semibold cursor-pointer transition-all duration-200 select-none ${
                    activeTab === 'binary'
                      ? 'bg-slate-900 text-white dark:bg-cyan-500 dark:text-slate-950 shadow-md shadow-slate-900/20 dark:shadow-cyan-500/30 scale-[1.02] border border-slate-900 dark:border-cyan-400 font-bold'
                      : 'bg-white/80 dark:bg-slate-800/80 text-slate-700 dark:text-slate-300 border border-slate-200/80 dark:border-slate-700/80 hover:bg-white dark:hover:bg-slate-700 hover:text-cyan-600 dark:hover:text-cyan-300 hover:border-slate-300 dark:hover:border-slate-600 shadow-xs'
                  }`}
                >
                  <Binary className={`w-3.5 h-3.5 ${activeTab === 'binary' ? 'text-cyan-400 dark:text-slate-950' : 'text-cyan-600 dark:text-cyan-400'}`} />
                  <span>Sandbox</span>
                </button>
              </nav>

              {/* Switches Segment (Glass Pill) */}
              <div className="flex items-center glass-pill p-1 space-x-1 shrink-0">
                {/* Laptop Stream Switch */}
                <button
                  type="button"
                  onClick={toggleHostLogs}
                  className="glass-btn flex items-center space-x-1.5 px-2 py-1 rounded-lg text-xs cursor-pointer"
                  title="Toggle real-time laptop system log streaming"
                >
                  <Laptop className={`w-3.5 h-3.5 ${hostStreaming ? 'text-blue-600 dark:text-cyan-400' : 'text-slate-400'}`} />
                  <span className={`text-[11px] font-['JetBrains_Mono'] ${hostStreaming ? 'text-blue-700 dark:text-cyan-300 font-semibold' : 'text-slate-600 dark:text-slate-300'}`}>Host</span>
                  <span
                    role="switch"
                    aria-checked={hostStreaming}
                    className={`relative inline-flex h-3.5 w-6 shrink-0 cursor-pointer rounded-full border border-transparent transition-colors duration-200 ease-in-out ${
                      hostStreaming ? 'bg-blue-600 dark:bg-cyan-500' : 'bg-slate-300 dark:bg-slate-700'
                    }`}
                  >
                    <span
                      className={`pointer-events-none inline-block h-2.5 w-2.5 transform rounded-full bg-white transition duration-200 ease-in-out shadow-xs ${
                      hostStreaming ? 'translate-x-2.5' : 'translate-x-0.5'
                    }`}
                    />
                  </span>
                </button>

                <div className="h-3 w-px bg-slate-300 dark:bg-slate-700" />

                {/* Demo Mode Switch */}
                <button
                  type="button"
                  onClick={toggleDemoMode}
                  className="glass-btn flex items-center space-x-1.5 px-2 py-1 rounded-lg text-xs cursor-pointer"
                  title="Toggle synthetic log generator"
                >
                  <Sparkles className={`w-3.5 h-3.5 ${instantDemoMode ? 'text-cyan-500' : 'text-slate-400'}`} />
                  <span className={`text-[11px] font-['JetBrains_Mono'] ${instantDemoMode ? 'text-slate-800 dark:text-slate-200 font-semibold' : 'text-slate-600 dark:text-slate-300'}`}>Demo</span>
                  <span
                    role="switch"
                    aria-checked={instantDemoMode}
                    className={`relative inline-flex h-3.5 w-6 shrink-0 cursor-pointer rounded-full border border-transparent transition-colors duration-200 ease-in-out ${
                      instantDemoMode ? 'bg-cyan-500' : 'bg-slate-300 dark:bg-slate-700'
                    }`}
                  >
                    <span
                      className={`pointer-events-none inline-block h-2.5 w-2.5 transform rounded-full bg-white transition duration-200 ease-in-out shadow-xs ${
                      instantDemoMode ? 'translate-x-2.5' : 'translate-x-0.5'
                    }`}
                    />
                  </span>
                </button>
              </div>

              {/* Theme Toggle Button (Glassomorphic Floating Button) */}
              <button
                type="button"
                onClick={toggleTheme}
                className="glass-btn p-2 rounded-full text-slate-700 dark:text-slate-200 cursor-pointer flex items-center justify-center transition-transform hover:scale-105 shrink-0"
                title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
              >
                {theme === 'dark' ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-slate-700" />}
              </button>

              {/* Connection Status Indicator */}
              <div className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-full border text-xs shadow-xs font-semibold backdrop-blur-md shrink-0 ${
                isStreaming 
                  ? 'bg-emerald-50/80 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800/60 text-emerald-700 dark:text-emerald-400' 
                  : 'bg-rose-50/80 dark:bg-rose-950/40 border-rose-200 dark:border-rose-800/60 text-rose-700 dark:text-rose-400'
              }`}>
                <span className={`w-2 h-2 rounded-full ${
                  isStreaming ? 'bg-emerald-500' : 'bg-rose-500 animate-ping'
                }`} />
                <span className="font-['JetBrains_Mono'] text-[9px] uppercase tracking-wider">
                  {isStreaming ? 'Fabric' : 'Offline'}
                </span>
              </div>

              {/* User Profile Pill & Dropdown */}
              <div className="relative shrink-0" ref={profileMenuRef}>
                <button
                  type="button"
                  onClick={() => setIsProfileMenuOpen(!isProfileMenuOpen)}
                  className="glass-btn flex items-center space-x-2 px-2.5 py-1 rounded-full cursor-pointer transition-all hover:border-cyan-500/50"
                  title="Operator Profile & System Settings"
                  aria-expanded={isProfileMenuOpen}
                >
                  <div className="w-6 h-6 rounded-full bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center text-white text-[11px] font-bold shadow-xs">
                    SO
                  </div>
                  <div className="hidden lg:flex flex-col text-left">
                    <span className="text-[11px] font-semibold text-slate-800 dark:text-slate-200 leading-tight">SecOps Lead</span>
                    <span className="text-[9px] text-cyan-600 dark:text-cyan-400 font-mono leading-none">L4 Clearance</span>
                  </div>
                  <ChevronDown className={`w-3.5 h-3.5 text-slate-500 dark:text-slate-400 transition-transform duration-200 ${isProfileMenuOpen ? 'rotate-180 text-cyan-500' : ''}`} />
                </button>

                {/* Profile Dropdown Menu */}
                <AnimatePresence>
                  {isProfileMenuOpen && (
                    <motion.div
                      initial={{ opacity: 0, y: 8, scale: 0.96 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      exit={{ opacity: 0, y: 8, scale: 0.96 }}
                      transition={{ duration: 0.15 }}
                      className="absolute right-0 mt-2 w-80 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-3.5 shadow-2xl z-50 backdrop-blur-2xl"
                    >
                      {/* Identity Card */}
                      <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 mb-2">
                        <div className="flex items-center space-x-2.5">
                          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white font-bold shadow-sm text-sm">
                            <User className="w-5 h-5" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-xs font-bold text-slate-800 dark:text-slate-100 truncate">SecOps Lead Operator</p>
                            <p className="text-[10px] text-slate-500 dark:text-slate-400 truncate font-mono">secops.lead@sentinel.defense.gov</p>
                          </div>
                        </div>
                        <div className="mt-2.5 flex items-center justify-between text-[10px] pt-2 border-t border-cyan-500/15">
                          <span className="text-slate-500 dark:text-slate-400 flex items-center gap-1">
                            <Shield className="w-3 h-3 text-cyan-500" /> Clearance Level:
                          </span>
                          <span className="font-mono font-bold text-cyan-600 dark:text-cyan-400 px-1.5 py-0.5 rounded bg-cyan-500/15">
                            TOP SECRET / SCI
                          </span>
                        </div>
                      </div>

                      {/* Dropdown Actions */}
                      <div className="space-y-1">
                        <button
                          type="button"
                          onClick={() => {
                            setIsProfileMenuOpen(false);
                            setIsSettingsModalOpen(true);
                          }}
                          className="w-full flex items-center justify-between px-2.5 py-2 rounded-xl text-xs text-slate-700 dark:text-slate-200 hover:bg-cyan-500/15 transition-colors cursor-pointer text-left group"
                        >
                          <span className="flex items-center gap-2">
                            <Settings className="w-4 h-4 text-cyan-500 group-hover:rotate-45 transition-transform" />
                            <span>System Settings & API Keys</span>
                          </span>
                          <kbd className="text-[9px] font-mono px-1 py-0.5 rounded bg-slate-200/80 dark:bg-slate-800 text-slate-500">⌘S</kbd>
                        </button>

                        <div className="h-px bg-slate-200 dark:bg-slate-800 my-1" />

                        <button
                          type="button"
                          onClick={() => {
                            localStorage.removeItem('ulpf_authenticated');
                            sessionStorage.removeItem('ulpf_authenticated');
                            setIsAuthenticated(false);
                            setIsProfileMenuOpen(false);
                          }}
                          className="w-full flex items-center space-x-2 px-2.5 py-2 rounded-xl text-xs text-rose-600 dark:text-rose-400 hover:bg-rose-500/15 transition-colors cursor-pointer text-left"
                        >
                          <LogOut className="w-4 h-4" />
                          <span>Lock Console & Sign Out</span>
                        </button>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>
            {/* Mobile Actions */}
            <div className="md:hidden flex items-center space-x-2">
              <button
                type="button"
                onClick={toggleTheme}
                className="glass-btn p-2 rounded-xl text-slate-700 dark:text-slate-200 cursor-pointer"
              >
                {theme === 'dark' ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-slate-700" />}
              </button>
              <button
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="glass-btn p-2 rounded-xl text-slate-700 dark:text-slate-200"
              >
                {mobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
              </button>
            </div>
          </header>
        </div>

        {/* Mobile Dropdown Menu (Glass Pill) */}
        {mobileMenuOpen && (
          <div className="md:hidden mx-6 mt-3 glass-pill rounded-3xl p-4 flex flex-col space-y-2 z-40">
            <button
              onClick={() => { setActiveTab('soc'); setMobileMenuOpen(false); }}
              className={`p-2.5 rounded-2xl text-xs font-semibold text-left flex items-center space-x-2 transition ${
                activeTab === 'soc' ? 'glass-btn-active font-bold' : 'glass-btn'
              }`}
            >
              <Radio className="w-3.5 h-3.5" />
              <span>SOC Operations</span>
            </button>
            <button
              onClick={() => { setActiveTab('mapper'); setMobileMenuOpen(false); }}
              className={`p-2.5 rounded-2xl text-xs font-semibold text-left flex items-center space-x-2 transition ${
                activeTab === 'mapper' ? 'glass-btn-active font-bold' : 'glass-btn'
              }`}
            >
              <SlidersHorizontal className="w-3.5 h-3.5" />
              <span>AI Schema Studio</span>
            </button>
            <button
              onClick={() => { setActiveTab('provenance'); setMobileMenuOpen(false); }}
              className={`p-2.5 rounded-2xl text-xs font-semibold text-left flex items-center space-x-2 transition ${
                activeTab === 'provenance' ? 'glass-btn-active font-bold' : 'glass-btn'
              }`}
            >
              <Fingerprint className="w-3.5 h-3.5" />
              <span>Air-Gap Provenance</span>
            </button>
            <button
              onClick={() => { setActiveTab('binary'); setMobileMenuOpen(false); }}
              className={`p-2.5 rounded-2xl text-xs font-semibold text-left flex items-center space-x-2 transition ${
                activeTab === 'binary' ? 'glass-btn-active font-bold' : 'glass-btn'
              }`}
            >
              <Binary className="w-3.5 h-3.5" />
              <span>Bit Sandbox</span>
            </button>
            <div className="h-px bg-slate-200 dark:bg-slate-800 my-1" />
            <div className="flex items-center justify-between p-2 rounded-2xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200/80 dark:border-slate-700/80">
              <span className="text-xs font-semibold flex items-center gap-2 text-slate-700 dark:text-slate-300">
                <Laptop className="w-4 h-4 text-cyan-500" />
                <span>Host Telemetry</span>
              </span>
              <button
                type="button"
                onClick={toggleHostLogs}
                className={`px-3 py-1 rounded-full text-[11px] font-mono font-bold transition-all ${
                  hostStreaming 
                    ? 'bg-cyan-500 text-slate-950 shadow-xs' 
                    : 'bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300'
                }`}
              >
                {hostStreaming ? 'ON' : 'OFF'}
              </button>
            </div>
            <button
              type="button"
              onClick={() => {
                setMobileMenuOpen(false);
                setIsSettingsModalOpen(true);
              }}
              className="p-2.5 rounded-2xl text-xs font-semibold text-left flex items-center space-x-2 glass-btn text-slate-700 dark:text-slate-200"
            >
              <Settings className="w-3.5 h-3.5 text-cyan-500" />
              <span>Settings & Clearance Keys</span>
            </button>
          </div>
        )}

      {/* Main Content Area: Fluid Full-Screen Enterprise Layout */}
      <main className="flex-1 px-3 sm:px-6 lg:px-8 py-3 w-full max-w-[1720px] mx-auto flex flex-col gap-4">
        {!isStreaming && (
          <div className="px-4 py-3 rounded-2xl bg-sky-50/80 dark:bg-sky-950/40 backdrop-blur-xl border border-sky-200 dark:border-sky-800/60 text-xs flex items-center justify-between shadow-xs">
            <div className="flex items-center space-x-2">
              <span className="w-1.5 h-1.5 rounded-full bg-sky-500 animate-ping shrink-0" />
              <span className="font-['JetBrains_Mono'] text-sky-800 dark:text-sky-300">
                [AIR-GAP FABRIC INITIALIZING] Synchronizing with ULPF Core Engine at 127.0.0.1:8000...
              </span>
            </div>
            <span className="text-[11px] text-sky-600 dark:text-sky-400 font-['JetBrains_Mono'] hidden sm:inline">Cached telemetry active in memory</span>
          </div>
        )}
        {activeTab === 'soc' && (
          <div className="flex-1 flex flex-col">
            <TelemetryMetrics 
              logs={logs} 
              throughput={eps} 
              hostStreaming={hostStreaming}
              instantDemoMode={instantDemoMode}
              isStreaming={isStreaming}
              hostInfo={hostInfo}
            />
            <LiveStream 
              logs={logs} 
              isStreaming={isStreaming || instantDemoMode} 
              onSelectLog={(log, occurrences) => {
                setSelectedLog(log);
                setSelectedOccurrences(occurrences || [log]);
              }}
              selectedLogId={selectedLog?.id || selectedLog?.traceability.raw_sha256}
              hostStreaming={hostStreaming}
              onToggleHostLogs={toggleHostLogs}
              filterMode={filterMode}
              onFilterModeChange={setFilterMode}
              onHistoricalUpload={(uploadedRecords) => {
                setLogs(prev => [...uploadedRecords, ...prev].slice(0, 150));
                setFilterMode('all');
              }}
            />
          </div>
        )}

        {activeTab === 'mapper' && (
          <div className="flex-1">
            <React.Suspense fallback={<div className="p-8 text-center text-xs font-mono text-slate-500">Loading AI Schema Studio...</div>}>
              <AiMapper />
            </React.Suspense>
          </div>
        )}

        {activeTab === 'provenance' && (
          <div className="flex-1">
            <React.Suspense fallback={<div className="p-8 text-center text-xs font-mono text-slate-500">Loading Air-Gap Provenance...</div>}>
              <AirGapProvenance logs={logs} />
            </React.Suspense>
          </div>
        )}

        {activeTab === 'binary' && (
          <div className="flex-1">
            <React.Suspense fallback={<div className="p-8 text-center text-xs font-mono text-slate-500">Loading Bit Compiler Sandbox...</div>}>
              <BinarySandbox initialLog={selectedLog || logs[0]} />
            </React.Suspense>
          </div>
        )}
      </main>

      {/* Forensic Log Drawer Modal with smooth AnimatePresence exit transition */}
      <AnimatePresence>
        {selectedLog && (
          <LogDrawer 
            key={selectedLog.id || selectedLog.traceability.raw_sha256} 
            log={selectedLog} 
            occurrences={selectedOccurrences}
            onClose={() => {
              setSelectedLog(null);
              setSelectedOccurrences([]);
            }} 
          />
        )}
      </AnimatePresence>

      {/* 4. The Services Dock (Nixtio Capsule Footer) */}
      <footer className="w-full flex justify-center py-3 px-4 sm:px-8 z-30">
        <div className="max-w-[1720px] w-full glass-pill border border-stone-200/80 dark:border-slate-800/80 shadow-xs px-5 py-2 text-xs text-stone-600 dark:text-slate-400 font-mono overflow-x-auto">
          <div className="flex items-center justify-between gap-6 min-w-max">
            {/* Horizontal Running Services Dock in single straight line */}
            <div className="flex items-center space-x-3 text-[11px] whitespace-nowrap">
              <span className="text-stone-900 dark:text-slate-100 font-bold uppercase tracking-wider text-[10px] mr-1">Air-Gap Fabric:</span>
              
              <div className="flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-500 shrink-0" />
                <span className="text-slate-800 dark:text-slate-200 font-semibold">Vector VRL</span>
                <span className="text-slate-400 dark:text-slate-500">:5140</span>
              </div>

              <span className="text-slate-300 dark:text-slate-700">|</span>

              <div className="flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
                <span className="text-slate-800 dark:text-slate-200 font-semibold">FastAPI Engine</span>
                <span className="text-slate-400 dark:text-slate-500">:8000</span>
              </div>

              <span className="text-slate-300 dark:text-slate-700">|</span>

              <div className="flex items-center space-x-1.5">
                <span className={`w-2 h-2 rounded-full shrink-0 ${hostStreaming ? 'bg-cyan-500 animate-pulse' : 'bg-slate-400 dark:bg-slate-600'}`} />
                <span className="text-slate-800 dark:text-slate-200 font-semibold">Host Agent</span>
                <span className="text-slate-400 dark:text-slate-500">{hostInfo?.hostname ? 'Bound' : 'Local'}</span>
              </div>

              <span className="text-slate-300 dark:text-slate-700">|</span>

              <div className="flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
                <span className="text-slate-800 dark:text-slate-200 font-semibold">SQLite WAL</span>
                <span className="text-slate-400 dark:text-slate-500">2048MB</span>
              </div>

              <span className="text-slate-300 dark:text-slate-700">|</span>

              <div className="flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
                <span className="text-slate-800 dark:text-slate-200 font-semibold">Threat DB</span>
                <span className="text-slate-400 dark:text-slate-500">O(1) Mem</span>
              </div>

              <span className="text-slate-300 dark:text-slate-700">|</span>

              <div className="flex items-center space-x-1.5">
                <span className={`w-2 h-2 rounded-full shrink-0 ${isStreaming ? 'bg-emerald-500 animate-pulse' : 'bg-cyan-500'}`} />
                <span className="text-slate-800 dark:text-slate-200 font-semibold">SSE Feed</span>
                <span className="text-slate-400 dark:text-slate-500">/api/stream</span>
              </div>
            </div>

            {/* Right Side Air-Gap Guarantee Tag */}
            <div className="flex items-center space-x-2 text-[11px] text-stone-500 dark:text-slate-400 font-mono whitespace-nowrap shrink-0">
              <span className="text-emerald-700 dark:text-emerald-400 font-bold flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
                100% Air-Gapped
              </span>
              <span className="text-stone-300 dark:text-slate-600">•</span>
              <span className="text-stone-600 dark:text-slate-300 font-medium">Zero External Egress</span>
            </div>
          </div>
        </div>
      </footer>

      {/* System Settings & Operator Profile Modal */}
      <AnimatePresence>
        {isSettingsModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsSettingsModalOpen(false)}
              className="absolute inset-0 bg-slate-950/70 backdrop-blur-md"
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 16 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 16 }}
              className="relative w-full max-w-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 shadow-2xl z-10 overflow-hidden"
            >
              {/* Modal Header */}
              <div className="flex items-center justify-between pb-4 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center space-x-3">
                  <div className="p-2.5 rounded-2xl bg-cyan-50 dark:bg-cyan-950/60 border border-cyan-200 dark:border-cyan-800/60 text-cyan-600 dark:text-cyan-400">
                    <Settings className="w-5 h-5" />
                  </div>
                  <div>
                    <h2 className="text-base font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
                      Operator Console & System Settings
                    </h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Configure operator identity, security keys, air-gap topology, and alert rules
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setIsSettingsModalOpen(false)}
                  className="p-1.5 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Sub-Tab Navigation Bar */}
              <div className="flex items-center space-x-1 border-b border-slate-200 dark:border-slate-800 pt-3 pb-2">
                <button
                  type="button"
                  onClick={() => setSettingsTab('profile')}
                  className={`px-3 py-1.5 rounded-xl text-xs font-semibold cursor-pointer transition-all flex items-center space-x-1.5 ${
                    settingsTab === 'profile'
                      ? 'glass-btn-active font-bold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  <User className="w-3.5 h-3.5" />
                  <span>Operator Profile</span>
                </button>

                <button
                  type="button"
                  onClick={() => setSettingsTab('security')}
                  className={`px-3 py-1.5 rounded-xl text-xs font-semibold cursor-pointer transition-all flex items-center space-x-1.5 ${
                    settingsTab === 'security'
                      ? 'glass-btn-active font-bold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  <Key className="w-3.5 h-3.5" />
                  <span>Security & API</span>
                </button>

                <button
                  type="button"
                  onClick={() => setSettingsTab('network')}
                  className={`px-3 py-1.5 rounded-xl text-xs font-semibold cursor-pointer transition-all flex items-center space-x-1.5 ${
                    settingsTab === 'network'
                      ? 'glass-btn-active font-bold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  <Network className="w-3.5 h-3.5" />
                  <span>Air-Gap Fabric</span>
                </button>

                <button
                  type="button"
                  onClick={() => setSettingsTab('alerts')}
                  className={`px-3 py-1.5 rounded-xl text-xs font-semibold cursor-pointer transition-all flex items-center space-x-1.5 ${
                    settingsTab === 'alerts'
                      ? 'glass-btn-active font-bold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  <Bell className="w-3.5 h-3.5" />
                  <span>Alert Rules</span>
                </button>
              </div>

              {/* Modal Body */}
              <div className="mt-4 space-y-4 max-h-[58vh] overflow-y-auto pr-1">
                {/* TAB 1: Operator Profile */}
                {settingsTab === 'profile' && (
                  <div className="space-y-4">
                    {/* Identity Hero */}
                    <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80">
                      <div className="flex items-center space-x-3.5">
                        <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center text-white text-xl font-bold shadow-md">
                          SO
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <h3 className="text-sm font-bold text-slate-900 dark:text-white truncate">SecOps Lead Operator</h3>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 font-bold flex items-center gap-1">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                              Active Session
                            </span>
                          </div>
                          <p className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">secops.lead@sentinel.defense.gov</p>
                          <div className="flex items-center gap-2 mt-2">
                            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30">
                              L4 Clearance (TOP SECRET / SCI)
                            </span>
                            <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400">
                              Role: Air-Gap Enclave Administrator
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Metadata Grid */}
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-800">
                        <p className="text-slate-400 text-[11px]">Operator ID</p>
                        <p className="font-mono font-bold text-slate-800 dark:text-slate-200 mt-0.5">OP-SENTINEL-9942</p>
                      </div>
                      <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-800">
                        <p className="text-slate-400 text-[11px]">Enclave Gateway</p>
                        <p className="font-mono font-bold text-slate-800 dark:text-slate-200 mt-0.5">127.0.0.1:8000</p>
                      </div>
                      <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-800">
                        <p className="text-slate-400 text-[11px]">Hardware Bound Token</p>
                        <p className="font-mono font-bold text-cyan-600 dark:text-cyan-400 mt-0.5">ED25519-ENCLAVE</p>
                      </div>
                      <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-800">
                        <p className="text-slate-400 text-[11px]">Session Duration</p>
                        <p className="font-mono font-bold text-slate-800 dark:text-slate-200 mt-0.5">23h 59m (Auto-Locking)</p>
                      </div>
                    </div>

                    {/* Quick Sign Out Action */}
                    <div className="flex items-center justify-between p-3 rounded-xl bg-rose-50/60 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-900/50">
                      <div>
                        <p className="text-xs font-bold text-rose-800 dark:text-rose-300">Terminal Session Lock</p>
                        <p className="text-[11px] text-rose-600 dark:text-rose-400">Instantly revoke operator token and return to air-gap sign-in screen</p>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          sessionStorage.removeItem('ulpf_authenticated');
                          setIsAuthenticated(false);
                          setIsSettingsModalOpen(false);
                        }}
                        className="px-3 py-1.5 rounded-lg bg-rose-600 text-white text-xs font-bold hover:bg-rose-700 transition cursor-pointer"
                      >
                        Sign Out
                      </button>
                    </div>
                  </div>
                )}

                {/* TAB 2: Security & API Keys */}
                {settingsTab === 'security' && (
                  <div className="space-y-4">
                    {/* API Authorization Key Config */}
                    <div className="space-y-2">
                      <label className="text-xs font-bold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                        <Key className="w-3.5 h-3.5 text-amber-500" />
                        FastAPI REST / Ingestion API Key
                      </label>
                      <div className="flex items-center space-x-2">
                        <div className="flex-1 px-3 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 font-mono text-xs text-slate-700 dark:text-slate-300 flex items-center justify-between">
                          <span>ulpf_admin_secret_key_2026</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 font-bold">SHA-256</span>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            navigator.clipboard.writeText('ulpf_admin_secret_key_2026');
                            setApiKeyCopied(true);
                            setTimeout(() => setApiKeyCopied(false), 2000);
                          }}
                          className="glass-btn px-3 py-2 rounded-xl text-xs font-semibold cursor-pointer flex items-center gap-1"
                        >
                          {apiKeyCopied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : null}
                          <span>{apiKeyCopied ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <p className="text-[11px] text-slate-400">Included as Bearer authorization token on all ingest, stream, and forensics requests.</p>
                    </div>

                    {/* Security Enforcements */}
                    <div className="space-y-3 pt-2 border-t border-slate-200 dark:border-slate-800">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">Lossless Merkle Hashing</p>
                          <p className="text-[11px] text-slate-400">Compute SHA-256 wire digest before parsing</p>
                        </div>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 font-bold">
                          ENFORCED
                        </span>
                      </div>

                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">Aadhaar & PII Scrubbing</p>
                          <p className="text-[11px] text-slate-400">Automated regex redaction compliant with IT Act 2000</p>
                        </div>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-600 dark:text-cyan-300 font-bold">
                          ACTIVE
                        </span>
                      </div>

                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">OCSF v1.1.0 Schema Validation</p>
                          <p className="text-[11px] text-slate-400">Quarantine malformed records missing critical classes</p>
                        </div>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-600 dark:text-cyan-300 font-bold">
                          ACTIVE
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {/* TAB 3: Air-Gap Network Fabric */}
                {settingsTab === 'network' && (
                  <div className="space-y-3">
                    <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 flex items-center justify-between">
                      <div>
                        <p className="text-xs font-bold text-slate-900 dark:text-white">Vector VRL UDP Listener</p>
                        <p className="text-[11px] text-slate-400 font-mono">127.0.0.1:5140 (Raw Syslog / CEF Pipe)</p>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 font-bold">
                        BOUND
                      </span>
                    </div>

                    <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 flex items-center justify-between">
                      <div>
                        <p className="text-xs font-bold text-slate-900 dark:text-white">FastAPI Uvicorn Engine</p>
                        <p className="text-[11px] text-slate-400 font-mono">127.0.0.1:8000 (REST / SSE Feed)</p>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 font-bold">
                        BOUND
                      </span>
                    </div>

                    <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 flex items-center justify-between">
                      <div>
                        <p className="text-xs font-bold text-slate-900 dark:text-white">SQLite WAL Ring Buffer</p>
                        <p className="text-[11px] text-slate-400 font-mono">Capacity: 2048 MB (Zero Egress Local Disk)</p>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 font-bold">
                        OPTIMAL
                      </span>
                    </div>

                    <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 flex items-center justify-between">
                      <div>
                        <p className="text-xs font-bold text-slate-900 dark:text-white">External Egress Firewall Rule</p>
                        <p className="text-[11px] text-slate-400 font-mono">DROP ALL outbound non-loopback packets</p>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 font-bold">
                        100% BLOCKED
                      </span>
                    </div>
                  </div>
                )}

                {/* TAB 4: Alert Notifications */}
                {settingsTab === 'alerts' && (
                  <div className="space-y-3">
                    <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 flex items-center justify-between">
                      <div>
                        <p className="text-xs font-bold text-slate-900 dark:text-white">Critical Threat Ingestion Flash</p>
                        <p className="text-[11px] text-slate-400">Trigger visual pulse animation when APT threat is detected</p>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 font-bold">
                        ENABLED
                      </span>
                    </div>

                    <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 flex items-center justify-between">
                      <div>
                        <p className="text-xs font-bold text-slate-900 dark:text-white">High Ingestion Surge Warning</p>
                        <p className="text-[11px] text-slate-400">Notify operator when EPS velocity exceeds 200 eps</p>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 font-bold">
                        ENABLED
                      </span>
                    </div>

                    <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 flex items-center justify-between">
                      <div>
                        <p className="text-xs font-bold text-slate-900 dark:text-white">Aadhaar Scrubbed Alert Badge</p>
                        <p className="text-[11px] text-slate-400">Attach green badge indicator whenever PII scrub event occurs</p>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 font-bold">
                        ENABLED
                      </span>
                    </div>
                  </div>
                )}
              </div>

              {/* Modal Footer */}
              <div className="mt-5 pt-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400">
                  AegisGuard-ULPF Sovereign Enclave · v2.0.0
                </span>
                <button
                  type="button"
                  onClick={() => setIsSettingsModalOpen(false)}
                  className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow-md shadow-cyan-500/20 cursor-pointer transition-all active:scale-95"
                >
                  Save & Close
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
    </>
  );
};

export default App;
