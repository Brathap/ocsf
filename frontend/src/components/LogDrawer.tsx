import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  X, 
  Copy, 
  Check, 
  FileCode, 
  Fingerprint, 
  ShieldAlert, 
  ShieldCheck, 
  Terminal, 
  Lock, 
  Hash, 
  Database, 
  Shield,
  Clock,
  Layers,
  Download
} from 'lucide-react';
import { exportLogs } from '../utils/exportFormats';
import { getAuthenticatedUrl } from '../utils/api';
import type { ULPFLogRecord } from '../types';

interface LogDrawerProps {
  log: ULPFLogRecord | null;
  onClose: () => void;
  occurrences?: ULPFLogRecord[];
}

export const LogDrawer: React.FC<LogDrawerProps> = ({ log, onClose, occurrences = [] }) => {
  const [activeTab, setActiveTab] = useState<'ocsf' | 'forensics' | 'raw' | 'timeline'>('ocsf');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showExport, setShowExport] = useState(false);
  const exportMenuRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!showExport) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target as Node)) {
        setShowExport(false);
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setShowExport(false);
    };
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [showExport]);

  const ocsfJson = React.useMemo(() => {
    return log?.normalized_data ? JSON.stringify(log.normalized_data, null, 2) : '';
  }, [log]);

  if (!log) return null;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const norm = (log?.normalized_data as any) || {};
  const trace = (log?.traceability as any) || {};
  const isMalicious = Boolean(norm?.enrichment?.is_malicious || norm?.threat?.is_malicious);
  const piiRedacted = Boolean(norm?.compliance?.pii_redacted || trace?.redacted_payload);

  const renderHighlightedRaw = (text?: string) => {
    if (!text) return <span className="text-slate-500 italic">No raw payload available</span>;
    if (!text.includes('[REDACTED_AADHAAR]')) {
      return <span>{text}</span>;
    }
    const parts = text.split('[REDACTED_AADHAAR]');
    return (
      <span>
        {parts.map((part, index) => (
          <React.Fragment key={index}>
            {part}
            {index < parts.length - 1 && (
              <span className="bg-amber-100 text-amber-900 border border-amber-300 px-2 py-0.5 rounded font-bold font-mono text-xs shadow-sm">
                [REDACTED_AADHAAR]
              </span>
            )}
          </React.Fragment>
        ))}
      </span>
    );
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex justify-end">
      {/* Backdrop clickable */}
      <motion.div 
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="absolute inset-0 bg-slate-900/30 backdrop-blur-xs" 
        onClick={onClose} 
      />

      {/* Sliding Forensic Panel: Clean Enterprise Panel */}
      <motion.div
        initial={{ x: '100%' }}
        animate={{ x: 0 }}
        exit={{ x: '100%' }}
        transition={{ type: 'spring', damping: 28, stiffness: 300 }}
        className="relative w-full max-w-2xl bg-white dark:bg-slate-950 border-l border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col h-full z-10 font-sans text-slate-800 dark:text-slate-100"
      >
          {/* Header */}
          <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 flex items-start justify-between">
            <div className="space-y-1">
              <div className="flex items-center space-x-3">
                <div className="p-2 rounded-lg bg-blue-50 dark:bg-slate-900 border border-blue-200 dark:border-blue-900/60 text-blue-600 dark:text-cyan-400">
                  <Fingerprint className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-extrabold text-slate-900 dark:text-white uppercase tracking-wider">
                    Deep Forensic Log Inspector
                  </h3>
                  <div className="flex items-center space-x-2 mt-1">
                    {Boolean(log?.is_simulated || norm.metadata?.source_type === 'demo') && (
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-800/80 tracking-wider">
                        SIMULATED
                      </span>
                    )}
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-50 dark:bg-blue-950/60 text-blue-800 dark:text-cyan-300 border border-blue-200 dark:border-blue-800/80 font-bold">
                      OCSF Class {norm.class_uid || 4001}
                    </span>
                    <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                      {norm.category_name || 'Network Activity'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-1.5">
              <div ref={exportMenuRef} className="relative">
                <button
                  type="button"
                  onClick={() => setShowExport(!showExport)}
                  className="p-1.5 px-2.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 text-xs font-semibold flex items-center space-x-1.5 transition cursor-pointer"
                  title="Export this record in any format"
                >
                  <Download className="w-3.5 h-3.5 text-blue-600 dark:text-cyan-400" />
                  <span>Export</span>
                </button>

                {showExport && (
                  <div 
                    className="absolute right-0 top-full mt-1.5 w-48 bg-white dark:bg-slate-900 rounded-xl shadow-2xl border border-slate-200 dark:border-slate-800 py-1.5 z-50 text-xs font-sans ring-1 ring-black/5"
                  >
                    <div className="px-3 py-1 text-[10px] uppercase font-bold text-slate-400 dark:text-slate-500 font-mono border-b border-slate-100 dark:border-slate-800 mb-1">
                      Download Record
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        exportLogs([log], 'jsonl.gz', `ulpf_log_${norm.class_uid || '4001'}`);
                        setShowExport(false);
                      }}
                      className="w-full text-left px-3 py-1.5 hover:bg-cyan-50 dark:hover:bg-slate-800 text-cyan-700 dark:text-cyan-300 font-bold flex items-center justify-between cursor-pointer border-b border-slate-100 dark:border-slate-800"
                    >
                      <span>Gzip Compressed</span>
                      <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-cyan-100 dark:bg-cyan-950/80 text-cyan-800 dark:text-cyan-300">.gz</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        exportLogs([log], 'compact_json', `ulpf_log_${norm.class_uid || '4001'}`);
                        setShowExport(false);
                      }}
                      className="w-full text-left px-3 py-1.5 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 flex items-center justify-between cursor-pointer"
                    >
                      <span>Ultra-Compact OCSF</span>
                      <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">.json</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        exportLogs([log], 'json', `ulpf_log_${norm.class_uid || '4001'}`);
                        setShowExport(false);
                      }}
                      className="w-full text-left px-3 py-1.5 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 flex items-center justify-between cursor-pointer"
                    >
                      <span>Full OCSF (Verbose)</span>
                      <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">.json</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        exportLogs([log], 'csv', `ulpf_log_${norm.class_uid || '4001'}`);
                        setShowExport(false);
                      }}
                      className="w-full text-left px-3 py-1.5 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 flex items-center justify-between cursor-pointer"
                    >
                      <span>CSV Spreadsheet</span>
                      <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">.csv</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        exportLogs([log], 'cef', `ulpf_log_${norm.class_uid || '4001'}`);
                        setShowExport(false);
                      }}
                      className="w-full text-left px-3 py-1.5 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 flex items-center justify-between cursor-pointer"
                    >
                      <span>ArcSight CEF</span>
                      <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">.cef</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        exportLogs([log], 'syslog', `ulpf_log_${norm.class_uid || '4001'}`);
                        setShowExport(false);
                      }}
                      className="w-full text-left px-3 py-1.5 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 flex items-center justify-between cursor-pointer"
                    >
                      <span>RFC5424 Syslog</span>
                      <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">.log</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        exportLogs([log], 'jsonl', `ulpf_log_${norm.class_uid || '4001'}`);
                        setShowExport(false);
                      }}
                      className="w-full text-left px-3 py-1.5 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 flex items-center justify-between cursor-pointer"
                    >
                      <span>JSONL Lines</span>
                      <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">.jsonl</span>
                    </button>
                  </div>
                )}
              </div>

              <button
                onClick={onClose}
                className="p-2 rounded-lg text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800 transition cursor-pointer"
                title="Close Drawer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Quick Threat & Status Summary Strip */}
          <div className="px-5 py-3 bg-slate-50 dark:bg-slate-900/90 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="flex items-center space-x-2.5">
              {isMalicious ? (
                <div className="flex items-center space-x-1.5 text-rose-700 dark:text-rose-300 font-semibold bg-rose-50 dark:bg-rose-950/60 px-3 py-1 rounded-md border border-rose-200 dark:border-rose-850">
                  <ShieldAlert className="w-4 h-4 animate-pulse text-rose-600 dark:text-rose-400" />
                  <span>Threat Actor: <strong>{norm.enrichment?.threat_actor || norm.threat?.actor || 'Threat Actor'}</strong></span>
                </div>
              ) : (
                <div className="flex items-center space-x-1.5 text-emerald-800 dark:text-emerald-300 font-semibold bg-emerald-50 dark:bg-emerald-950/60 px-3 py-1 rounded-md border border-emerald-200 dark:border-emerald-800">
                  <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                  <span>Benign Verified Traffic</span>
                </div>
              )}

              {piiRedacted && (
                <div className="flex items-center space-x-1 text-amber-800 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/60 px-2.5 py-1 rounded-md border border-amber-200 dark:border-amber-800">
                  <Lock className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
                  <span>Aadhaar PII Scrubbed</span>
                </div>
              )}
            </div>

            <div className="font-mono text-xs text-slate-500 dark:text-slate-400">
              Severity: <strong className="text-slate-900 dark:text-white font-bold">{norm.severity || 'Informational'}</strong>
            </div>
          </div>

          {/* Tab Navigation */}
          <div className="flex border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 px-5 pt-3 gap-3 text-xs">
            <button
              onClick={() => setActiveTab('ocsf')}
              className={`pb-3 px-3.5 font-bold border-b-2 transition-all flex items-center space-x-2 cursor-pointer ${
                activeTab === 'ocsf'
                  ? 'border-blue-600 dark:border-cyan-400 text-blue-600 dark:text-cyan-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>OCSF Normalized JSON</span>
            </button>
            <button
              onClick={() => setActiveTab('forensics')}
              className={`pb-3 px-3.5 font-bold border-b-2 transition-all flex items-center space-x-2 cursor-pointer ${
                activeTab === 'forensics'
                  ? 'border-blue-600 dark:border-cyan-400 text-blue-600 dark:text-cyan-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <Hash className="w-3.5 h-3.5" />
              <span>Forensic Provenance</span>
            </button>
            <button
              onClick={() => setActiveTab('raw')}
              className={`pb-3 px-3.5 font-bold border-b-2 transition-all flex items-center space-x-2 cursor-pointer ${
                activeTab === 'raw'
                  ? 'border-blue-600 dark:border-cyan-400 text-blue-600 dark:text-cyan-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Original Raw String</span>
            </button>
            {occurrences && occurrences.length > 1 && (
              <button
                type="button"
                onClick={() => setActiveTab('timeline')}
                className={`pb-3 px-3.5 font-bold border-b-2 transition-all flex items-center space-x-2 cursor-pointer ${
                  activeTab === 'timeline'
                    ? 'border-blue-600 dark:border-cyan-400 text-blue-600 dark:text-cyan-400'
                    : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                <Clock className="w-3.5 h-3.5 text-blue-600 dark:text-cyan-400" />
                <span>Repeat Timeline</span>
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold bg-blue-100 dark:bg-cyan-950 text-blue-800 dark:text-cyan-300">
                  {occurrences.length}x
                </span>
              </button>
            )}
          </div>

          {/* Drawer Body */}
          <div className="flex-1 overflow-y-auto p-5 space-y-4">
            {activeTab === 'ocsf' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
                  <span>Standard: <strong className="text-slate-900 dark:text-white font-mono font-bold">OCSF v1.1.0</strong></span>
                  <button
                    onClick={() => copyToClipboard(ocsfJson, 'ocsf')}
                    className="flex items-center space-x-1.5 px-3 py-1 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 transition"
                  >
                    {copiedKey === 'ocsf' ? <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === 'ocsf' ? 'Copied' : 'Copy JSON'}</span>
                  </button>
                </div>
                <pre className="bg-slate-900 dark:bg-slate-950 text-emerald-400 border border-slate-800 rounded-xl p-4 text-xs font-mono leading-relaxed overflow-x-auto shadow-inner">
                  {ocsfJson}
                </pre>
              </div>
            )}

            {activeTab === 'forensics' && (
              <div className="space-y-4 text-xs">
                {/* Cryptographic SHA-256 / Demo Hash */}
                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider flex items-center gap-1.5 text-xs">
                      <Fingerprint className="w-4 h-4 text-blue-600 dark:text-cyan-400" />
                      {log?.is_simulated || norm.metadata?.source_type === 'demo'
                        ? 'Simulated Demo Hash (Non-Cryptographic)'
                        : 'SHA-256 Non-Repudiation Wire Hash'}
                    </span>
                    <button
                      onClick={() => copyToClipboard(trace.raw_sha256 || trace.raw_hash || '', 'sha')}
                      className="px-2.5 py-1 rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700 flex items-center space-x-1 font-mono font-semibold"
                    >
                      {copiedKey === 'sha' ? <Check className="w-3 h-3 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>Copy</span>
                    </button>
                  </div>
                  <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800 font-mono text-blue-800 dark:text-cyan-300 break-all select-all text-xs font-semibold">
                    {trace.raw_sha256 || trace.raw_hash || 'Validated'}
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {log?.is_simulated || norm.metadata?.source_type === 'demo'
                      ? 'Simulated 32-bit test hash generated in-browser for mock demonstration. NOT SHA-256.'
                      : 'Calculated in-flight before any normalization transforms. Provides evidentiary proof of authenticity.'}
                  </p>
                </div>

                {/* Base64 Wire Source */}
                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider flex items-center gap-1.5 text-xs">
                      <Database className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                      Base64 Encoded Wire Payload
                    </span>
                    <button
                      onClick={() => copyToClipboard(trace.raw_base64 || trace.raw_log_base64 || '', 'b64')}
                      className="px-2.5 py-1 rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700 flex items-center space-x-1 font-mono font-semibold"
                    >
                      {copiedKey === 'b64' ? <Check className="w-3 h-3 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>Copy</span>
                    </button>
                  </div>
                  <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800 font-mono text-slate-600 dark:text-slate-300 break-all max-h-28 overflow-y-auto text-xs">
                    {trace.raw_base64 || trace.raw_log_base64 || 'Base64 Wire Ingested'}
                  </div>
                </div>

                {/* Threat Correlation Details */}
                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-2.5">
                  <span className="font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider text-xs flex items-center gap-1.5">
                    <Shield className="w-4 h-4 text-rose-600 dark:text-rose-400" />
                    Threat Intel Provenance
                  </span>
                  <div className="grid grid-cols-2 gap-3 text-slate-700 dark:text-slate-300 font-mono text-xs">
                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                      <span className="text-slate-500 dark:text-slate-400 block text-[10px] uppercase font-bold">Source IP Address</span>
                      <span className="text-slate-900 dark:text-white font-bold">{norm.src_endpoint?.ip || '0.0.0.0'}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                      <span className="text-slate-500 dark:text-slate-400 block text-[10px] uppercase font-bold">Threat Attribution</span>
                      <span className={isMalicious ? 'text-rose-700 dark:text-rose-400 font-bold' : 'text-slate-700 dark:text-slate-300'}>
                        {norm.enrichment?.threat_actor || norm.threat?.actor || 'None'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Court-Admissible Forensic Bundle Export Card */}
                <div className="bg-blue-50/70 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900/60 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <span className="font-bold text-blue-950 dark:text-blue-200 text-xs block">
                      SHA-256 Integrity-Hashed Evidence Bundle
                    </span>
                    <span className="text-[11px] text-slate-600 dark:text-slate-400 block mt-0.5">
                      Packages raw.wire, ocsf.json, and signed SHA-256 manifest into a verifiable .zip archive.
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      const targetId = log.id || trace.raw_sha256 || 'latest_event';
                      window.open(getAuthenticatedUrl(`/api/export-forensic/${targetId}`), '_blank');
                    }}
                    className="px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 dark:bg-cyan-600 dark:hover:bg-cyan-500 text-white font-mono text-xs font-bold flex items-center justify-center space-x-1.5 transition cursor-pointer shadow-xs shrink-0"
                    title="Download forensic evidence .zip archive"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download .zip Bundle</span>
                  </button>
                </div>

                {/* RFC 6962 Cryptographic Merkle Inclusion Proof */}
                <MerkleProofViewer eventId={log.id || trace.raw_sha256 || ''} />
              </div>
            )}

            {activeTab === 'raw' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
                  <span>Protocol: <strong className="text-slate-900 dark:text-white font-mono">UDP Syslog 514 (RFC5424/CEF)</strong></span>
                  <button
                    onClick={() => copyToClipboard(trace.sanitized_raw || trace.redacted_payload || norm.activity_name || '', 'raw')}
                    className="flex items-center space-x-1.5 px-3 py-1 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 transition"
                  >
                    {copiedKey === 'raw' ? <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === 'raw' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <div className="bg-slate-900 dark:bg-slate-950 text-slate-100 border border-slate-800 rounded-xl p-4 font-mono text-xs leading-relaxed break-all shadow-inner">
                  {renderHighlightedRaw(trace.sanitized_raw || trace.redacted_payload || norm.activity_name || '')}
                </div>
                {piiRedacted && (
                  <div className="p-3.5 bg-amber-50 dark:bg-amber-950/50 border border-amber-200 dark:border-amber-800 rounded-lg text-amber-900 dark:text-amber-200 text-xs flex items-center space-x-2">
                    <Lock className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
                    <span>Highlighted 12-digit token was identified as Aadhaar PII and sanitized in-memory by Vector remap.</span>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'timeline' && occurrences && occurrences.length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs text-slate-600 dark:text-slate-300 bg-blue-50 dark:bg-slate-900 border border-blue-200 dark:border-slate-800 p-3 rounded-lg">
                  <div className="flex items-center space-x-2">
                    <Layers className="w-4 h-4 text-blue-600 dark:text-cyan-400" />
                    <span>
                      Total Occurrences Collapsed: <strong className="text-blue-900 dark:text-cyan-300 font-bold">{occurrences.length} instances</strong>
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">Chronological Arrival Order</span>
                </div>

                <div className="space-y-2 max-h-[460px] overflow-y-auto pr-1">
                  {occurrences.map((item, idx) => {
                    const itemTrace = (item.traceability as any) || {};
                    const itemNorm = (item.normalized_data as any) || {};
                    let timeFormatted = 'Just now';
                    if (itemTrace.ingest_timestamp) {
                      const d = new Date(itemTrace.ingest_timestamp);
                      const base = d.toLocaleTimeString([], { hour12: false });
                      const ms = String(d.getMilliseconds()).padStart(3, '0');
                      timeFormatted = `${base}.${ms}`;
                    }
                    const itemSha = (itemTrace.raw_sha256 || itemTrace.raw_hash || '0000000000').substring(0, 12);

                    return (
                      <div 
                        key={item.id || `timeline-${idx}`}
                        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-3 hover:border-blue-300 dark:hover:border-cyan-600 transition-all font-mono text-xs flex flex-col space-y-1.5 shadow-2xs"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <span className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 font-bold text-[11px]">
                              Pulse #{occurrences.length - idx}
                            </span>
                            <span className="text-blue-700 dark:text-cyan-400 font-bold flex items-center space-x-1">
                              <Clock className="w-3 h-3" />
                              <span>{timeFormatted}</span>
                            </span>
                          </div>
                          <span className="text-slate-400 dark:text-slate-500 text-[10px]" title={itemTrace.raw_sha256}>
                            SHA: {itemSha}...
                          </span>
                        </div>
                        <div className="text-slate-600 dark:text-slate-300 bg-slate-50 dark:bg-slate-950 p-2 rounded border border-slate-150 dark:border-slate-800 text-[11px] break-all">
                          {itemTrace.sanitized_raw || itemNorm.activity_name || 'Host Telemetry'}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="p-4 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span className="font-mono text-[11px]">
              SHA: {(trace.raw_sha256 || trace.raw_hash || '0000000000000000').substring(0, 16)}...
            </span>
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 dark:bg-cyan-600 dark:hover:bg-cyan-500 text-white font-medium transition cursor-pointer"
            >
              Close Inspector
            </button>
          </div>
        </motion.div>
      </div>
    );
};

interface MerkleProofViewerProps {
  eventId: string;
}

const MerkleProofViewer: React.FC<MerkleProofViewerProps> = ({ eventId }) => {
  const [loading, setLoading] = useState(false);
  const [proofData, setProofData] = useState<any>(null);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchProof = async () => {
    if (!eventId) return;
    setLoading(true);
    setError(null);
    setVerified(null);
    try {
      const res = await fetch(`/api/merkle/proof/${encodeURIComponent(eventId)}`, {
        headers: { "X-API-Key": "ulpf_admin_secret_key_2026" }
      });
      if (!res.ok) {
        throw new Error(`Event not archived in active SQLite ledger (Status ${res.status})`);
      }
      const data = await res.json();
      setProofData(data);

      // Immediately verify RFC 6962 proof
      const vRes = await fetch(`/api/merkle/verify-proof`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": "ulpf_admin_secret_key_2026"
        },
        body: JSON.stringify({
          leaf_data: data.leaf_data,
          leaf_index: data.leaf_index,
          total_leaves: data.total_leaves,
          proof: data.proof,
          merkle_root: data.merkle_root
        })
      });
      if (vRes.ok) {
        const vData = await vRes.json();
        setVerified(vData.verified);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load Merkle proof");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-700 rounded-xl p-4 space-y-3 font-mono text-xs">
      <div className="flex items-center justify-between">
        <span className="font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5 font-sans">
          <Database className="w-4 h-4 text-emerald-400" />
          RFC 6962 Cryptographic Merkle Inclusion Proof
        </span>
        <button
          type="button"
          onClick={fetchProof}
          disabled={loading || !eventId}
          className="px-2.5 py-1 rounded bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 font-bold transition cursor-pointer disabled:opacity-50"
        >
          {loading ? "Verifying..." : proofData ? "Re-verify Proof" : "Verify In Ledger"}
        </button>
      </div>

      {error && (
        <div className="text-amber-400 text-[11px] bg-amber-950/40 p-2 rounded border border-amber-800">
          {error}
        </div>
      )}

      {proofData && (
        <div className="space-y-2 pt-1 border-t border-slate-800 text-[11px]">
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Cryptographic Status:</span>
            {verified ? (
              <span className="text-emerald-400 font-bold flex items-center gap-1">
                <Check className="w-3.5 h-3.5" /> 100% MATHEMATICALLY VERIFIED
              </span>
            ) : (
              <span className="text-rose-400 font-bold">VERIFICATION FAILED</span>
            )}
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Leaf Index / Total Leaves:</span>
            <span className="text-slate-200">
              #{proofData.leaf_index} / {proofData.total_leaves} leaves
            </span>
          </div>
          <div>
            <span className="text-slate-400 block mb-0.5">Merkle Root (SHA-256):</span>
            <div className="p-1.5 bg-slate-950 rounded text-emerald-300 text-[10px] break-all border border-slate-800">
              {proofData.merkle_root}
            </div>
          </div>
          <div>
            <span className="text-slate-400 block mb-0.5">Proof Audit Path ({proofData.proof?.length || 0} hashes):</span>
            <div className="max-h-24 overflow-y-auto space-y-1 p-1 bg-slate-950 rounded border border-slate-800">
              {proofData.proof?.map((p: any, i: number) => (
                <div key={i} className="text-[9px] flex items-center justify-between text-slate-300">
                  <span className="text-slate-500">Step {i + 1} ({p.direction}):</span>
                  <span className="truncate max-w-[280px]">{p.hash}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

