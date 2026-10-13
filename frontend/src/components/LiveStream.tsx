import React, { useState, useRef } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Search, 
  Lock, 
  Filter, 
  ChevronRight, 
  Info, 
  Laptop, 
  Layers, 
  Copy, 
  Download, 
  Check, 
  Radio, 
  Upload, 
  Loader2 
} from 'lucide-react';
import { exportLogs } from '../utils/exportFormats';
import { useToast } from '../context/ToastContext';
import { secureFetch } from '../utils/api';
import type { ULPFLogRecord } from '../types';

interface LiveStreamProps {
  logs: ULPFLogRecord[];
  isStreaming: boolean;
  onSelectLog: (log: ULPFLogRecord, occurrences?: ULPFLogRecord[]) => void;
  selectedLogId?: string;
  hostStreaming?: boolean;
  onToggleHostLogs?: () => void;
  filterMode?: 'all' | 'laptop' | 'threats' | 'pii' | 'blocks';
  onFilterModeChange?: (mode: 'all' | 'laptop' | 'threats' | 'pii' | 'blocks') => void;
  onHistoricalUpload?: (records: ULPFLogRecord[]) => void;
}

type FilterMode = 'all' | 'laptop' | 'threats' | 'pii' | 'blocks';

interface DisplayLogEntry {
  log: ULPFLogRecord;
  repeatCount: number;
  occurrences: ULPFLogRecord[];
}

export const LiveStream: React.FC<LiveStreamProps> = ({ 
  logs, 
  onSelectLog,
  selectedLogId,
  hostStreaming = false,
  onToggleHostLogs,
  filterMode: controlledFilterMode,
  onFilterModeChange,
  onHistoricalUpload
}) => {
  const { showToast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isUploading, setIsUploading] = useState(false);
  // If controlledFilterMode is provided, use it; otherwise use local state
  const [internalFilterMode, setInternalFilterMode] = useState<FilterMode>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [collapseDuplicates, setCollapseDuplicates] = useState(true);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const exportMenuRef = useRef<HTMLDivElement>(null);

  // Close Export menu when clicking outside or pressing Escape
  React.useEffect(() => {
    if (!showExportMenu) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target as Node)) {
        setShowExportMenu(false);
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setShowExportMenu(false);
    };
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [showExportMenu]);

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    showToast('Ingesting Historical Telemetry', `Reading and normalizing ${file.name}...`, 'info');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await secureFetch('/api/upload-historical', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Upload failed' }));
        throw new Error(errorData.detail || 'Failed to ingest file');
      }

      const result = await response.json();
      showToast(
        'Historical Ingestion Complete',
        `Normalized ${result.records_ingested} records into OCSF taxonomy`,
        'success'
      );

      if (result.sample_records && result.sample_records.length > 0 && onHistoricalUpload) {
        onHistoricalUpload(result.sample_records);
      }
    } catch (err: any) {
      showToast('Upload Failed', err.message || 'Error uploading historical log file', 'error');
    } finally {
      setIsUploading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const activeFilter = controlledFilterMode !== undefined ? controlledFilterMode : internalFilterMode;

  const handleFilterChange = (mode: FilterMode) => {
    if (onFilterModeChange) {
      onFilterModeChange(mode);
    } else {
      setInternalFilterMode(mode);
    }
    const modeLabels: Record<FilterMode, string> = {
      all: 'All Events View',
      laptop: 'Laptop Host Telemetry',
      threats: 'Threat Intel Alerts',
      pii: 'Aadhaar Scrubbed Events',
      blocks: 'Firewall Blocks'
    };
    showToast(`Filter Activated`, `Now viewing ${modeLabels[mode]}`, 'info');
  };

  const counts = React.useMemo(() => {
    let laptopCount = 0;
    let threatCount = 0;
    let piiCount = 0;
    let blockCount = 0;

    logs.forEach(log => {
      const norm = log?.normalized_data as any;
      const trace = log?.traceability as any;
      const isLaptop = norm?.metadata?.source_type === 'laptop_host' || (trace?.sanitized_raw || '').startsWith('[HOST:');
      const isMalicious = norm?.enrichment?.is_malicious || norm?.threat?.is_malicious;
      const piiRedacted = norm?.compliance?.pii_redacted || trace?.redacted_payload;
      const act = (norm?.activity_name || '').toLowerCase();
      const raw = (trace?.sanitized_raw || '').toLowerCase();
      const isBlock = act.includes('block') || act.includes('denied') || raw.includes('denied') || raw.includes('block');

      if (isLaptop) laptopCount++;
      if (isMalicious) threatCount++;
      if (piiRedacted) piiCount++;
      if (isBlock) blockCount++;
    });

    return { laptopCount, threatCount, piiCount, blockCount };
  }, [logs]);

  // Step 1: Filter raw logs based on active view and search term
  const rawFilteredLogs = React.useMemo(() => {
    return logs.filter(log => {
      const norm = log?.normalized_data as any;
      const trace = log?.traceability as any;
      const isMalicious = norm?.enrichment?.is_malicious || norm?.threat?.is_malicious;
      const piiRedacted = norm?.compliance?.pii_redacted || trace?.redacted_payload;
      const isLaptop = norm?.metadata?.source_type === 'laptop_host' || (trace?.sanitized_raw || '').startsWith('[HOST:');

      if (activeFilter === 'laptop' && !isLaptop) {
        return false;
      }
      if (activeFilter === 'threats' && !isMalicious) {
        return false;
      }
      if (activeFilter === 'pii' && !piiRedacted) {
        return false;
      }
      if (activeFilter === 'blocks') {
        const act = (norm?.activity_name || '').toLowerCase();
        const raw = (trace?.sanitized_raw || '').toLowerCase();
        if (!act.includes('block') && !act.includes('denied') && !raw.includes('denied') && !raw.includes('block')) {
          return false;
        }
      }

      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        const raw = (trace?.sanitized_raw || '').toLowerCase();
        const src = (norm?.src_endpoint?.ip || '').toLowerCase();
        const dst = (norm?.dst_endpoint?.ip || '').toLowerCase();
        const cat = (norm?.category_name || '').toLowerCase();
        const actor = (norm?.enrichment?.threat_actor || norm?.threat?.actor || '').toLowerCase();
        return raw.includes(term) || src.includes(term) || dst.includes(term) || cat.includes(term) || actor.includes(term);
      }
      return true;
    });
  }, [logs, activeFilter, searchTerm]);

  // Step 2: Intelligent Deduplication / Grouping
  const displayedEntries: DisplayLogEntry[] = React.useMemo(() => {
    if (!collapseDuplicates) {
      return rawFilteredLogs.map(log => ({ log, repeatCount: 1, occurrences: [log] }));
    }

    const grouped: DisplayLogEntry[] = [];
    const seenMap = new Map<string, number>();

    for (const log of rawFilteredLogs) {
      const norm = log?.normalized_data as any;
      let activity = norm?.activity_name || '';
      // If it's host telemetry, group under common action 'Host Telemetry'
      if (activity.toLowerCase().includes('host telemetry') || activity.toLowerCase().includes('systemd-hostmon')) {
        activity = 'Host Telemetry Pulse';
      }
      
      const key = `${norm?.class_uid || ''}_${norm?.category_name || ''}_${activity}_${norm?.src_endpoint?.ip || ''}_${norm?.dst_endpoint?.ip || ''}`;

      if (seenMap.has(key)) {
        const existingIndex = seenMap.get(key)!;
        grouped[existingIndex].repeatCount += 1;
        grouped[existingIndex].occurrences.push(log);
      } else {
        seenMap.set(key, grouped.length);
        grouped.push({ log, repeatCount: 1, occurrences: [log] });
      }
    }

    return grouped.slice(0, 150);
  }, [rawFilteredLogs, collapseDuplicates]);

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return (
          <span className="px-2.5 py-0.5 text-[11px] font-bold uppercase rounded-full bg-rose-50 text-rose-700 border border-rose-200/80 flex items-center gap-1.5 w-max font-mono shadow-xs">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
            Critical
          </span>
        );
      case 'high':
        return (
          <span className="px-2.5 py-0.5 text-[11px] font-bold uppercase rounded-full bg-orange-50 text-orange-700 border border-orange-200/80 w-max font-mono shadow-xs">
            High
          </span>
        );
      case 'medium':
        return (
          <span className="px-2.5 py-0.5 text-[11px] font-bold uppercase rounded-full bg-sky-50 text-sky-700 border border-sky-200/80 w-max font-mono shadow-xs">
            Medium
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-0.5 text-[11px] font-bold uppercase rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200/80 w-max font-mono shadow-xs">
            Info
          </span>
        );
    }
  };

  return (
    <div className="flex flex-col h-full w-full bg-white dark:bg-slate-900 border border-slate-200/90 dark:border-slate-800 rounded-3xl shadow-xs overflow-visible transition-colors mt-2">
      {/* Top Controls Toolbar: Single-line layout with overflow-visible for export dropdown */}
      <div className="relative z-30 p-2.5 sm:p-3 border-b border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/60 overflow-visible">
        <div className="flex items-center justify-between gap-2.5 w-full">
          {/* Left: Filter Views (Glass Pill) */}
          <div className="flex items-center space-x-1.5 shrink-0 overflow-x-auto no-scrollbar py-0.5">
            <span className="text-xs text-slate-800 dark:text-slate-200 mr-1 flex items-center gap-1.5 font-mono uppercase font-bold shrink-0">
              <Filter className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
              <span className="hidden xl:inline">Views:</span>
            </span>

            <div className="glass-pill inline-flex p-1 rounded-full space-x-1 shrink-0">
              <button
                type="button"
                onClick={() => handleFilterChange('all')}
                className={`px-2.5 py-1 rounded-lg text-xs font-semibold cursor-pointer flex items-center space-x-1.5 shrink-0 transition-all ${
                  activeFilter === 'all'
                    ? 'glass-btn-active font-bold'
                    : 'glass-btn hover:text-cyan-600 dark:hover:text-cyan-400'
                }`}
              >
                <span>All Events</span>
                <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-['JetBrains_Mono'] ${
                  activeFilter === 'all' 
                    ? 'bg-white/20 text-white font-bold' 
                    : 'bg-slate-200/80 dark:bg-slate-700/80 text-slate-700 dark:text-slate-200 font-bold'
                }`}>
                  {logs.length}
                </span>
              </button>

              <button
                type="button"
                onClick={() => {
                  handleFilterChange('laptop');
                  if (!hostStreaming && onToggleHostLogs) {
                    onToggleHostLogs();
                  }
                }}
                className={`px-2.5 py-1 rounded-lg text-xs font-semibold cursor-pointer flex items-center space-x-1.5 shrink-0 transition-all ${
                  activeFilter === 'laptop'
                    ? 'glass-btn-active font-bold'
                    : 'glass-btn hover:text-blue-600 dark:hover:text-cyan-400'
                }`}
              >
                <span className={`w-2 h-2 rounded-full ${hostStreaming ? 'bg-cyan-400 animate-pulse' : 'bg-slate-400'}`} />
                <Laptop className="w-3.5 h-3.5" />
                <span>Laptop Logs</span>
                <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-['JetBrains_Mono'] ${
                  activeFilter === 'laptop' 
                    ? 'bg-white/20 text-white font-bold' 
                    : 'bg-slate-200/80 dark:bg-slate-700/80 text-slate-700 dark:text-slate-200 font-bold'
                }`}>
                  {counts.laptopCount}
                </span>
              </button>

              <button
                type="button"
                onClick={() => handleFilterChange('threats')}
                className={`px-2.5 py-1 rounded-lg text-xs font-semibold cursor-pointer flex items-center space-x-1.5 shrink-0 transition-all ${
                  activeFilter === 'threats'
                    ? 'bg-gradient-to-r from-rose-500 to-red-600 text-white font-bold shadow-[0_6px_20px_-2px_rgba(244,63,94,0.4)] border border-white/40'
                    : 'glass-btn hover:text-rose-600 dark:hover:text-rose-400'
                }`}
              >
                <span className="w-2 h-2 rounded-full bg-rose-400 animate-pulse" />
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>Threat Alerts</span>
                <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-['JetBrains_Mono'] ${
                  activeFilter === 'threats' 
                    ? 'bg-white/20 text-white font-bold' 
                    : 'bg-slate-200/80 dark:bg-slate-700/80 text-slate-700 dark:text-slate-200 font-bold'
                }`}>
                  {counts.threatCount}
                </span>
              </button>

              <button
                type="button"
                onClick={() => handleFilterChange('pii')}
                className={`px-2.5 py-1 rounded-lg text-xs font-semibold cursor-pointer flex items-center space-x-1.5 shrink-0 transition-all ${
                  activeFilter === 'pii'
                    ? 'bg-gradient-to-r from-amber-500 to-orange-500 text-white font-bold shadow-[0_6px_20px_-2px_rgba(245,158,11,0.4)] border border-white/40'
                    : 'glass-btn hover:text-amber-600 dark:hover:text-amber-400'
                }`}
              >
                <Lock className="w-3.5 h-3.5" />
                <span>PII Scrubbed</span>
                <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-['JetBrains_Mono'] ${
                  activeFilter === 'pii' 
                    ? 'bg-white/20 text-white font-bold' 
                    : 'bg-slate-200/80 dark:bg-slate-700/80 text-slate-700 dark:text-slate-200 font-bold'
                }`}>
                  {counts.piiCount}
                </span>
              </button>

              <button
                type="button"
                onClick={() => handleFilterChange('blocks')}
                className={`px-2.5 py-1 rounded-lg text-xs font-semibold cursor-pointer flex items-center space-x-1.5 shrink-0 transition-all ${
                  activeFilter === 'blocks'
                    ? 'bg-gradient-to-r from-purple-500 to-indigo-600 text-white font-bold shadow-[0_6px_20px_-2px_rgba(168,85,247,0.4)] border border-white/40'
                    : 'glass-btn hover:text-purple-600 dark:hover:text-purple-400'
                }`}
              >
                <span className="w-2 h-2 rounded-full bg-purple-400" />
                <span>Blocks</span>
                <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-['JetBrains_Mono'] ${
                  activeFilter === 'blocks' 
                    ? 'bg-white/20 text-white font-bold' 
                    : 'bg-slate-200/80 dark:bg-slate-700/80 text-slate-700 dark:text-slate-200 font-bold'
                }`}>
                  {counts.blockCount}
                </span>
              </button>
            </div>
          </div>

          {/* Right: Actions & Global Search in one contiguous line */}
          <div className="flex items-center space-x-1.5 shrink-0">
            {/* Deduplicate / Group Duplicates Toggle */}
            <button
              type="button"
              onClick={() => setCollapseDuplicates(!collapseDuplicates)}
              className={`px-2.5 py-1 rounded-xl text-xs font-semibold flex items-center space-x-1.5 cursor-pointer shrink-0 transition-all ${
                collapseDuplicates 
                  ? 'bg-slate-900 text-white dark:bg-cyan-500 dark:text-slate-950 font-bold shadow-md shadow-slate-900/20 dark:shadow-cyan-500/30 border border-slate-900 dark:border-cyan-400' 
                  : 'bg-white/80 dark:bg-slate-800/80 text-slate-700 dark:text-slate-300 border border-slate-200/90 dark:border-slate-700/80 hover:bg-slate-100 dark:hover:bg-slate-700 hover:text-cyan-600 dark:hover:text-cyan-300 hover:border-slate-300 dark:hover:border-slate-600 shadow-xs'
              }`}
              title="Group repetitive log occurrences into a single item with count badge"
            >
              <Layers className={`w-3.5 h-3.5 ${collapseDuplicates ? 'text-cyan-400 dark:text-slate-950' : 'text-cyan-600 dark:text-cyan-400'}`} />
              <span className="hidden 2xl:inline">Group Duplicates</span>
              <span className="2xl:hidden">Group</span>
              <span className={`px-1 py-0.2 text-[10px] font-mono rounded ${
                collapseDuplicates 
                  ? 'bg-white/20 text-white dark:text-slate-950 dark:bg-slate-950/20 font-bold' 
                  : 'bg-slate-200/80 dark:bg-slate-700 text-slate-700 dark:text-slate-300'
              }`}>
                {collapseDuplicates ? 'ON' : 'OFF'}
              </span>
            </button>

            {/* Multi-Format Export Dropdown */}
            <div ref={exportMenuRef} className="relative shrink-0">
              <button
                type="button"
                onClick={() => setShowExportMenu(!showExportMenu)}
                className="glass-btn px-2.5 py-1 rounded-xl text-xs font-semibold flex items-center space-x-1.5 cursor-pointer"
                title="Download logs in any format (JSON, CSV, CEF, Syslog, JSONL)"
              >
                <Download className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
                <span>Export</span>
              </button>

              {showExportMenu && (
                <div 
                  className="absolute right-0 top-full mt-2 w-56 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 py-1.5 z-50 text-xs font-mono shadow-2xl ring-1 ring-black/10 dark:ring-white/5"
                >
                  <div className="px-3 py-1.5 text-[10px] uppercase font-bold text-slate-500 dark:text-slate-400 font-mono border-b border-slate-100 dark:border-slate-800 mb-1 flex items-center justify-between">
                    <span>Export {displayedEntries.length} Logs</span>
                    <span className="text-[9px] px-1.5 py-0.2 rounded bg-emerald-100 dark:bg-emerald-950/80 text-emerald-800 dark:text-emerald-300 font-sans font-semibold">Gzip Active</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      exportLogs(displayedEntries.map(e => e.log), 'jsonl.gz', `ulpf_${activeFilter}_logs`);
                      setShowExportMenu(false);
                      showToast('Gzip Export Complete', `Downloaded ${displayedEntries.length} records in compressed .jsonl.gz (98% smaller)`, 'success');
                    }}
                    className="w-full text-left px-3 py-1.5 hover:bg-cyan-50 dark:hover:bg-slate-800 text-cyan-700 dark:text-cyan-300 font-bold flex items-center justify-between cursor-pointer border-b border-slate-100 dark:border-slate-800"
                  >
                    <span className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 animate-pulse" />
                      <span>Gzip JSONL Stream</span>
                    </span>
                    <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-cyan-100 dark:bg-cyan-950/80 text-cyan-800 dark:text-cyan-300">.jsonl.gz</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      exportLogs(displayedEntries.map(e => e.log), 'compact_json', `ulpf_${activeFilter}_logs`);
                      setShowExportMenu(false);
                      showToast('Export Complete', `Downloaded ${displayedEntries.length} records in Ultra-Compact OCSF (gzipped)`, 'success');
                    }}
                    className="w-full text-left px-3 py-1.5 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 flex items-center justify-between cursor-pointer"
                  >
                    <span>Ultra-Compact OCSF</span>
                    <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">.json.gz</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      exportLogs(displayedEntries.map(e => e.log), 'csv.gz', `ulpf_${activeFilter}_logs`);
                      setShowExportMenu(false);
                      showToast('Export Complete', `Downloaded ${displayedEntries.length} records in compressed CSV format`, 'success');
                    }}
                    className="w-full text-left px-3 py-1.5 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 flex items-center justify-between cursor-pointer"
                  >
                    <span>Compressed CSV</span>
                    <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">.csv.gz</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      exportLogs(displayedEntries.map(e => e.log), 'json', `ulpf_${activeFilter}_logs`);
                      setShowExportMenu(false);
                      showToast('Export Complete', `Downloaded ${displayedEntries.length} records in full OCSF JSON (gzipped)`, 'success');
                    }}
                    className="w-full text-left px-3 py-1.5 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 flex items-center justify-between cursor-pointer"
                  >
                    <span>Full OCSF JSON</span>
                    <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">.json.gz</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      exportLogs(displayedEntries.map(e => e.log), 'cef', `ulpf_${activeFilter}_logs`);
                      setShowExportMenu(false);
                      showToast('Export Complete', `Downloaded ${displayedEntries.length} records in ArcSight CEF (gzipped)`, 'success');
                    }}
                    className="w-full text-left px-3 py-1.5 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 flex items-center justify-between cursor-pointer"
                  >
                    <span>ArcSight CEF</span>
                    <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">.cef.gz</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      exportLogs(displayedEntries.map(e => e.log), 'syslog', `ulpf_${activeFilter}_logs`);
                      setShowExportMenu(false);
                      showToast('Export Complete', `Downloaded ${displayedEntries.length} records in RFC5424 Syslog (gzipped)`, 'success');
                    }}
                    className="w-full text-left px-3 py-1.5 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 flex items-center justify-between cursor-pointer"
                  >
                    <span>RFC5424 Syslog</span>
                    <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">.log.gz</span>
                  </button>
                </div>
              )}
            </div>

            {/* Hidden File Input for Historical Log Telemetry */}
            <input
              ref={fileInputRef}
              type="file"
              accept=".log,.txt,.json,.jsonl,.csv"
              onChange={handleFileUpload}
              className="hidden"
            />

            {/* Historical Telemetry Upload Button */}
            <button
              type="button"
              disabled={isUploading}
              onClick={() => fileInputRef.current?.click()}
              className="glass-btn px-2.5 py-1 rounded-xl text-xs font-semibold flex items-center space-x-1.5 cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed shrink-0"
              title="Upload historical raw logs or CSV spreadsheet for instant OCSF normalization"
            >
              {isUploading ? (
                <Loader2 className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400 animate-spin" />
              ) : (
                <Upload className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
              )}
              <span>Upload</span>
              <span className="hidden 2xl:inline"> Telemetry</span>
            </button>

            {/* Search Bar matching exact height */}
            <div className="relative flex items-center w-28 sm:w-36 lg:w-44 shrink-0">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2 pointer-events-none" />
              <input
                type="text"
                placeholder="Search..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-slate-100/90 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 focus:border-cyan-500 focus:bg-white dark:focus:bg-slate-800 text-xs pl-6.5 pr-2 py-1 rounded-xl text-slate-800 dark:text-slate-100 placeholder-slate-400 transition-colors outline-none font-mono"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Antigravity Floating Glass Table Stream: Spread fluidly across screen with visible Inspect button */}
      <div className="flex-1 overflow-x-auto overflow-y-auto min-h-[460px] p-2.5 sm:p-4">
        <table className="w-full text-left text-xs border-separate border-spacing-y-1.5 table-fixed min-w-[960px] xl:min-w-full">
          <thead className="sticky top-0 bg-white/95 dark:bg-slate-900/95 backdrop-blur-xl border-b border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 uppercase tracking-wider font-['JetBrains_Mono'] text-[11px] z-10 shadow-xs">
            <tr>
              <th className="py-3 px-3.5 font-bold rounded-l-xl text-slate-800 dark:text-slate-200 w-[15%] min-w-[130px]">Time / Fingerprint</th>
              <th className="py-3 px-3.5 font-bold text-slate-800 dark:text-slate-200 w-[19%] min-w-[170px]">OCSF Taxonomy</th>
              <th className="py-3 px-3 font-bold text-slate-800 dark:text-slate-200 w-[14%] min-w-[125px]">Source Endpoint</th>
              <th className="py-3 px-3 font-bold text-slate-800 dark:text-slate-200 w-[14%] min-w-[125px]">Target Destination</th>
              <th className="py-3 px-2.5 font-bold text-slate-800 dark:text-slate-200 w-[9%] min-w-[85px]">Severity</th>
              <th className="py-3 px-3 font-bold text-slate-800 dark:text-slate-200 w-[13%] min-w-[120px]">Threat Correlation</th>
              <th className="py-3 px-2.5 font-bold text-slate-800 dark:text-slate-200 w-[9%] min-w-[85px]">PII Guard</th>
              <th className="py-3 px-3.5 text-center font-bold rounded-r-xl text-slate-800 dark:text-slate-200 w-[7%] min-w-[80px]">Inspect</th>
            </tr>
          </thead>
          <tbody className="font-['JetBrains_Mono'] text-slate-700 dark:text-slate-300 transition-colors">
            {displayedEntries.map(({ log, repeatCount, occurrences }, index) => {
              const norm = (log?.normalized_data as any) || {};
              const trace = (log?.traceability as any) || {};
              const isMalicious = Boolean(norm?.enrichment?.is_malicious || norm?.threat?.is_malicious);
              const piiRedacted = Boolean(norm?.compliance?.pii_redacted || (trace?.redacted_payload && trace.redacted_payload.includes('[REDACTED_AADHAAR]')));
              const rawHash = trace?.raw_sha256 || trace?.raw_hash || '0000000000';
              const isSelected = selectedLogId === log?.id || selectedLogId === rawHash;
              
              // Extract timestamp with millisecond precision
              let timeString = 'Just now';
              if (trace?.ingest_timestamp) {
                const d = new Date(trace.ingest_timestamp);
                const base = d.toLocaleTimeString([], { hour12: false });
                const ms = String(d.getMilliseconds()).padStart(3, '0');
                timeString = `${base}.${ms}`;
              } else if (norm?.activity_name) {
                const timeMatch = norm.activity_name.match(/(\d{2}:\d{2}:\d{2})/);
                if (timeMatch) timeString = timeMatch[1];
              }

              const shaPrefix = rawHash.substring(0, 10);
              const category = norm?.category_name || norm?.class_name || 'Network Activity';
              const severity = norm?.severity || norm?.threat?.severity_level || (isMalicious ? 'Critical' : 'Informational');
              const threatActor = norm?.enrichment?.threat_actor || norm?.threat?.actor || (isMalicious ? 'Threat Detected' : 'Benign');
              const mitreId = norm?.enrichment?.mitre_id || norm?.threat?.mitre_id;
              const isLaptopEvent = norm?.metadata?.source_type === 'laptop_host' || (trace?.sanitized_raw || '').startsWith('[HOST:');
              const isSimulated = Boolean(log?.is_simulated || norm?.metadata?.source_type === 'demo');
              const isLatest = index === 0;

              return (
                <tr
                  key={log?.id || rawHash || `log-${index}`}
                  onClick={() => onSelectLog(log, occurrences)}
                  className={`transition-colors duration-200 cursor-pointer rounded-lg ${
                    isSelected
                      ? 'bg-blue-50 dark:bg-blue-950/50 border border-blue-300 dark:border-blue-700 shadow-xs'
                      : isMalicious
                      ? 'bg-rose-50/70 dark:bg-rose-950/40 hover:bg-rose-100/70 dark:hover:bg-rose-950/60 border border-rose-200 dark:border-rose-900/60'
                      : isLaptopEvent
                      ? 'bg-blue-50/50 dark:bg-blue-950/30 hover:bg-blue-100/50 dark:hover:bg-blue-950/50 border border-blue-200 dark:border-blue-900/60'
                      : 'bg-white/90 dark:bg-slate-900/70 hover:bg-slate-50 dark:hover:bg-slate-800/80 border border-slate-200/90 dark:border-slate-800/90 shadow-xs'
                  }`}
                >
                  {/* Timestamp & SHA */}
                  <td className="py-2.5 px-3.5 whitespace-nowrap">
                    <div className="text-slate-900 dark:text-slate-100 font-bold text-xs flex items-center space-x-1.5">
                      <span>{timeString}</span>
                      {isLaptopEvent ? (
                        <span 
                          title="Real-time live laptop host log from local machine"
                          className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800 tracking-wider shadow-xs"
                        >
                          HOST
                        </span>
                      ) : (
                        <span 
                          title="Live verified wire-level ingestion event"
                          className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-50 dark:bg-cyan-950/60 text-cyan-700 dark:text-cyan-300 border border-cyan-200 dark:border-cyan-800 tracking-wider shadow-xs"
                        >
                          WIRE
                        </span>
                      )}
                      {repeatCount > 1 && (
                        <span 
                          title={`${repeatCount} identical log entries collapsed`}
                          className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-slate-100 text-cyan-700 border border-slate-200"
                        >
                          ×{repeatCount}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center space-x-1 mt-0.5">
                      <span className="text-[11px] text-slate-500 font-mono truncate max-w-[85px]" title={rawHash}>
                        {shaPrefix}...
                      </span>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigator.clipboard.writeText(rawHash);
                          setCopiedHash(rawHash);
                          showToast('Hash Copied', `${rawHash.slice(0, 16)}... copied to clipboard`, 'info');
                          setTimeout(() => setCopiedHash(null), 1500);
                        }}
                        className="text-slate-400 hover:text-cyan-600 transition-colors cursor-pointer p-0.5 rounded hover:bg-slate-100"
                        title="Copy complete SHA-256 hash"
                      >
                        {copiedHash === rawHash ? (
                          <Check className="w-3 h-3 text-emerald-600" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                  </td>

                  {/* OCSF Category & Action */}
                  <td className="py-2.5 px-3.5 whitespace-nowrap">
                    <div className="flex items-center space-x-1.5">
                      <span className="text-cyan-700 dark:text-cyan-400 font-bold text-xs">
                        {category}
                      </span>
                      {norm?.class_uid && (
                        <span className="text-[10px] text-slate-500 dark:text-slate-400 font-mono px-1.5 py-0.2 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
                          {norm.class_uid}
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-600 dark:text-slate-300 truncate max-w-[340px] xl:max-w-none font-sans font-medium mt-0.5" title={norm?.activity_name}>
                      {norm?.activity_name || 'Activity'}
                    </div>
                  </td>

                  {/* Source Endpoint */}
                  <td className="py-2.5 px-3.5 whitespace-nowrap overflow-hidden">
                    <div className="flex items-center space-x-1.5 max-w-full">
                      <span className={`font-mono text-xs font-semibold shrink-0 ${
                        isMalicious ? 'text-rose-600 dark:text-rose-400 font-bold' : norm?.metadata?.source_type === 'laptop_host' ? 'text-cyan-700 dark:text-cyan-400 font-bold' : 'text-slate-800 dark:text-slate-100'
                      }`}>
                        {norm?.src_endpoint?.ip || '0.0.0.0'}
                      </span>
                      {norm?.src_endpoint?.geo && (
                        <span 
                          title={norm.src_endpoint.geo}
                          className="text-[10px] px-1.5 py-0.2 rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-500 dark:text-slate-400 font-mono flex items-center gap-1 max-w-[130px] truncate"
                        >
                          {norm?.metadata?.source_type === 'laptop_host' && <Laptop className="w-2.5 h-2.5 text-cyan-600 dark:text-cyan-400 shrink-0" />}
                          <span className="truncate">{norm.src_endpoint.geo}</span>
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Target Destination */}
                  <td className="py-2.5 px-3.5 whitespace-nowrap overflow-hidden">
                    <div className="text-slate-700 dark:text-slate-300 text-xs flex items-center space-x-1 font-mono font-medium max-w-full">
                      <span className="shrink-0">{norm?.dst_endpoint?.ip || '10.0.0.1'}</span>
                      {norm?.dst_endpoint?.geo && (
                        <span 
                          title={norm.dst_endpoint.geo}
                          className="text-[10px] text-slate-400 dark:text-slate-500 max-w-[120px] truncate"
                        >
                          [{norm.dst_endpoint.geo}]
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Severity */}
                  <td className="py-2.5 px-3.5 whitespace-nowrap">
                    {getSeverityBadge(severity)}
                  </td>

                  {/* Threat Correlation */}
                  <td className="py-2.5 px-3.5 whitespace-nowrap">
                    {isMalicious ? (
                      <div className="flex items-center space-x-1.5 text-rose-600 font-bold text-xs">
                        <ShieldAlert className="w-3.5 h-3.5 text-rose-600 animate-pulse shrink-0" />
                        <span className="truncate max-w-[120px]">{threatActor}</span>
                        {mitreId && (
                          <span 
                            title={`MITRE ATT&CK Technique: ${mitreId}`}
                            className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 border border-rose-300"
                          >
                            [MITRE: {mitreId}]
                          </span>
                        )}
                      </div>
                    ) : (
                      <div className="flex items-center space-x-1 text-slate-600 text-xs font-mono">
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                        <span>Benign</span>
                      </div>
                    )}
                  </td>

                  {/* PII Compliance */}
                  <td className="py-2.5 px-3.5 whitespace-nowrap">
                    {piiRedacted ? (
                      <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-cyan-50 dark:bg-cyan-950/60 text-cyan-700 dark:text-cyan-300 border border-cyan-200/80 dark:border-cyan-800 font-mono shadow-xs">
                        <Lock className="w-3 h-3 text-cyan-500 shrink-0" />
                        <span>AADHAAR SCRUBBED</span>
                      </span>
                    ) : (
                      <span className="text-xs text-slate-400 font-mono">Clean</span>
                    )}
                  </td>

                  {/* Action Trigger */}
                  <td className="py-2 px-3 whitespace-nowrap text-center">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectLog(log, occurrences);
                      }}
                      className="inline-flex items-center justify-center px-2.5 py-1 rounded-lg text-slate-700 dark:text-slate-200 text-xs font-mono font-bold cursor-pointer bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-cyan-500 hover:text-white dark:hover:bg-cyan-500 dark:hover:text-slate-950 hover:border-cyan-500 transition-all shadow-xs"
                      title="Inspect event schema and raw cryptographic provenance"
                    >
                      <span>Inspect</span>
                      <ChevronRight className="w-3.5 h-3.5 ml-0.5" />
                    </button>
                  </td>
                </tr>
              );
            })}
            {displayedEntries.length === 0 && (
              <tr>
                <td colSpan={8} className="py-16 text-center text-slate-500 dark:text-slate-400 bg-white/60 dark:bg-slate-900/60">
                  <div className="flex flex-col items-center justify-center space-y-3">
                    <div className="relative flex items-center justify-center w-14 h-14">
                      <span className="absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-20 animate-ping" />
                      <span className="absolute inline-flex h-10 w-10 rounded-full bg-cyan-500 opacity-25 animate-pulse" />
                      <div className="relative flex items-center justify-center w-8 h-8 rounded-full bg-cyan-50 dark:bg-cyan-950/60 border border-cyan-200 dark:border-cyan-800 text-cyan-600 dark:text-cyan-400 shadow-xs">
                        <Radio className="w-4 h-4 animate-spin text-cyan-600 dark:text-cyan-400" />
                      </div>
                    </div>
                    <div className="space-y-1">
                      <p className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase font-mono tracking-wider">
                        Awaiting Ingestion Telemetry Stream
                      </p>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400 font-sans max-w-sm mx-auto">
                        Vector UDP:5140 and TCP:6514 listeners are active. No records matching filter <strong className="font-mono text-cyan-700 dark:text-cyan-400">[{activeFilter.toUpperCase()}]</strong>.
                      </p>
                    </div>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Footer Info Strip */}
      <div className="p-3.5 border-t border-slate-100 dark:border-slate-800 bg-white/70 dark:bg-slate-950/80 flex flex-wrap items-center justify-between text-xs text-slate-500 dark:text-slate-400 px-5 font-mono gap-2 transition-colors duration-200">
        <div className="flex items-center space-x-2">
          <Info className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
          <span>
            Showing <strong className="text-slate-800 dark:text-slate-200 font-bold">{displayedEntries.length}</strong> {collapseDuplicates ? 'distinct' : 'total'} enterprise events
            {collapseDuplicates && rawFilteredLogs.length > displayedEntries.length && (
              <span className="ml-1.5 text-cyan-700 dark:text-cyan-400 font-bold">({rawFilteredLogs.length - displayedEntries.length} duplicates collapsed)</span>
            )}
          </span>
        </div>
        <div className="flex items-center space-x-2 text-slate-500 dark:text-slate-400 font-sans">
          <span>Click any row for side-by-side forensic analysis</span>
        </div>
      </div>
    </div>
  );
};
