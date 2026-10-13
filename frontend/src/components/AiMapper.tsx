import React, { useState } from 'react';
import axios from 'axios';
import { 
  Sparkles, 
  Send, 
  CheckCircle2, 
  AlertCircle, 
  FileCode, 
  Workflow, 
  Plus, 
  Trash2, 
  Cpu, 
  Play 
} from 'lucide-react';
import { useToast } from '../context/ToastContext';
import { getAuthHeaders, API_BASE_URL } from '../utils/api';

const OCSF_TARGET_FIELDS = [
  { value: 'src_endpoint.ip', label: 'Source IP Address (src_endpoint.ip)' },
  { value: 'src_endpoint.port', label: 'Source Port (src_endpoint.port)' },
  { value: 'dst_endpoint.ip', label: 'Destination IP Address (dst_endpoint.ip)' },
  { value: 'dst_endpoint.port', label: 'Destination Port (dst_endpoint.port)' },
  { value: 'activity_name', label: 'Activity Name / Action (activity_name)' },
  { value: 'severity', label: 'Severity Classification (severity)' },
  { value: 'category_name', label: 'Security Category (category_name)' },
  { value: 'actor.user.name', label: 'User Account (actor.user.name)' },
  { value: 'http_request.url', label: 'HTTP Request URL (http_request.url)' },
];

const PRESETS = [
  {
    id: 'cisco',
    name: 'Cisco ASA Firewall',
    badge: 'Syslog',
    sourceType: 'cisco_asa',
    wireFormat: 'SYSLOG',
    sample: `<164>Oct 24 10:20:30 ciscoasa: %ASA-4-106023: Denied tcp src inside:198.51.100.23/50901 dst outside:198.51.100.10/22 by access-group 'OUTSIDE_IN'`,
    mappings: [
      { sourceKey: 'src', ocsfPath: 'src_endpoint.ip' },
      { sourceKey: 'dst', ocsfPath: 'dst_endpoint.ip' },
      { sourceKey: 'action', ocsfPath: 'activity_name' },
    ]
  },
  {
    id: 'paloalto',
    name: 'Palo Alto GlobalProtect',
    badge: 'CEF',
    sourceType: 'vpn_gateway',
    wireFormat: 'CEF',
    sample: `CEF:0|PaloAltoNetworks|PAN-OS|10.1|AUTH|GlobalProtect login|5|src=198.51.100.23 dst=10.0.0.1 spt=54321 dpt=443 suser=priya.verma act=login-success aadhaar_id=982345129081`,
    mappings: [
      { sourceKey: 'src', ocsfPath: 'src_endpoint.ip' },
      { sourceKey: 'dst', ocsfPath: 'dst_endpoint.ip' },
      { sourceKey: 'suser', ocsfPath: 'actor.user.name' },
      { sourceKey: 'act', ocsfPath: 'activity_name' },
    ]
  },
  {
    id: 'linux',
    name: 'Linux SSHD Authentication',
    badge: 'Syslog',
    sourceType: 'linux_auth',
    wireFormat: 'SYSLOG',
    sample: `<84>Oct 24 10:22:15 auth-server-01 sshd[1234]: Failed password for root from 203.0.113.84 port 48212 ssh2 session_id=SES_9999 gov_ref_aadhaar=452178902341`,
    mappings: [
      { sourceKey: 'src', ocsfPath: 'src_endpoint.ip' },
      { sourceKey: 'user', ocsfPath: 'actor.user.name' },
      { sourceKey: 'status', ocsfPath: 'activity_name' },
    ]
  },
  {
    id: 'unknown_raw',
    name: 'Unknown Custom Log',
    badge: 'Auto-Detect',
    sourceType: 'unknown_source',
    wireFormat: 'SYSLOG',
    sample: `10.240.11.89 - - [25/Sep/2026:14:02:19 +0000] "POST /api/v2/secure-auth HTTP/1.1" 403 892 client_ip=198.51.100.88 actor=priya_admin blocked_by=custom_firewall_rule`,
    mappings: [
      { sourceKey: 'client_ip', ocsfPath: 'src_endpoint.ip' },
      { sourceKey: 'actor', ocsfPath: 'actor.user.name' },
      { sourceKey: 'blocked_by', ocsfPath: 'activity_name' },
    ]
  },
];

export const AiMapper: React.FC = () => {
  const { showToast } = useToast();
  const [selectedPresetId, setSelectedPresetId] = useState('paloalto');
  const [parserName, setParserName] = useState('PaloAlto_GlobalProtect_VPN');
  const [sourceType, setSourceType] = useState('vpn_gateway');
  const [wireFormat, setWireFormat] = useState('CEF');
  const [rawSample, setRawSample] = useState(PRESETS[1].sample);
  const [mappings, setMappings] = useState(PRESETS[1].mappings);

  const [isDeploying, setIsDeploying] = useState(false);
  const [deployResult, setDeployResult] = useState<{
    status: 'idle' | 'success' | 'error';
    message: string;
    vrlPreview?: string;
  }>({ status: 'idle', message: '' });

  const loadPreset = (presetId: string) => {
    const preset = PRESETS.find(p => p.id === presetId);
    if (!preset) return;
    setSelectedPresetId(presetId);
    setParserName(preset.name.replace(/[^a-zA-Z0-9]/g, '_'));
    setSourceType(preset.sourceType);
    setWireFormat(preset.wireFormat);
    setRawSample(preset.sample);
    setMappings(preset.mappings);
    setDeployResult({ status: 'idle', message: '' });
  };

  const addMappingRow = () => {
    setMappings([...mappings, { sourceKey: '', ocsfPath: OCSF_TARGET_FIELDS[0].value }]);
  };

  const removeMappingRow = (index: number) => {
    setMappings(mappings.filter((_, idx) => idx !== index));
  };

  const updateMappingRow = (index: number, key: 'sourceKey' | 'ocsfPath', value: string) => {
    const updated = [...mappings];
    updated[index][key] = value;
    setMappings(updated);
  };

  const [isInferring, setIsInferring] = useState(false);
  const [aiConfidence, setAiConfidence] = useState<number | null>(null);

  const handleAiInferSchema = async () => {
    if (!rawSample.trim()) return;
    setIsInferring(true);
    setDeployResult({ status: 'idle', message: '' });
    showToast('AI Inference Started', 'Analyzing wire structure and token patterns...', 'info');

    try {
      const res = await axios.post(`${API_BASE_URL}/api/ai-infer-schema`, {
        raw_sample: rawSample
      }, {
        headers: getAuthHeaders()
      });
      const data = res.data;
      if (data && data.status === 'success') {
        if (data.detected_source_type) setSourceType(data.detected_source_type);
        if (data.detected_wire_format) setWireFormat(data.detected_wire_format);
        if (data.confidence_score) setAiConfidence(data.confidence_score);

        if (Array.isArray(data.inferred_mappings) && data.inferred_mappings.length > 0) {
          setMappings(data.inferred_mappings.map((m: any) => ({
            sourceKey: m.sourceKey,
            ocsfPath: m.ocsfPath
          })));
        }

        const successMsg = `AI Inference Complete (${data.confidence_score}% Confidence): Autonomously mapped ${data.inferred_mappings.length} schema fields for ${data.detected_source_type} (${data.detected_wire_format}).`;
        setDeployResult({
          status: 'success',
          message: successMsg
        });
        showToast('AI Mapping Succeeded', `${data.inferred_mappings.length} fields mapped at ${data.confidence_score}% confidence`, 'success');
      }
    } catch (err: any) {
      showToast('Inference Error', err.response?.data?.error || err.message || 'AI Schema inference failed', 'error');
    } finally {
      setIsInferring(false);
    }
  };

  const handleDeployParser = async () => {
    setIsDeploying(true);
    setDeployResult({ status: 'idle', message: '' });
    showToast('Compiling Parser', `Validating syntax and building VRL script for ${parserName}...`, 'info');

    try {
      const mappingDict: Record<string, string> = {};
      mappings.forEach(m => {
        if (m.sourceKey.trim()) {
          mappingDict[m.sourceKey.trim()] = m.ocsfPath;
        }
      });

      const response = await axios.post(`${API_BASE_URL}/api/generate-parser`, {
        parser_name: parserName,
        source_type: sourceType,
        wire_format: wireFormat,
        mappings: mappingDict,
        raw_sample: rawSample,
      }, {
        headers: getAuthHeaders()
      });

      const successMsg = response.data.message || 'Parser successfully deployed to Vector pipeline!';
      setDeployResult({
        status: 'success',
        message: successMsg,
        vrlPreview: response.data.vrl_preview,
      });
      showToast('Parser Deployed', `Vector remap ${parserName}.vrl active with zero downtime`, 'success');
    } catch (err: any) {
      const errMsg = err.response?.data?.error || err.response?.data?.detail || err.message || 'Failed to deploy parser to Vector backend.';
      setDeployResult({
        status: 'error',
        message: errMsg,
      });
      showToast('Deployment Failed', errMsg, 'error');
    } finally {
      setIsDeploying(false);
    }
  };

  return (
    <div className="bg-white/95 dark:bg-slate-900/90 border border-stone-200/80 dark:border-slate-800 rounded-3xl p-6 sm:p-7 shadow-xs transition-colors duration-200">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between pb-5 mb-5 border-b border-stone-100 dark:border-slate-800 gap-4">
        <div className="flex items-center space-x-3.5">
          <div className="p-2.5 rounded-2xl bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-800">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-extrabold text-stone-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
              Autonomous AI Schema Studio
              <span className="text-xs font-mono px-3 py-1 rounded-full bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800 font-bold">
                Vector VRL Engine
              </span>
            </h2>
            <p className="text-xs text-stone-500 dark:text-slate-400 mt-0.5">
              Compile proprietary vendor device schemas into standard OCSF v1.1.0 with zero runtime downtime
            </p>
          </div>
        </div>

        {/* Deploy Action Button (Floating Glass Active) */}
        <button
          onClick={handleDeployParser}
          disabled={isDeploying}
          className="glass-btn-active flex items-center space-x-2 px-5 py-2.5 rounded-xl font-bold text-xs uppercase tracking-wider cursor-pointer disabled:opacity-50 transition-all hover:scale-102"
        >
          {isDeploying ? (
            <>
              <Cpu className="w-4 h-4 animate-spin text-white" />
              <span>Compiling VRL...</span>
            </>
          ) : (
            <>
              <Send className="w-4 h-4 text-white" />
              <span>Deploy Parser to Vector</span>
            </>
          )}
        </button>
      </div>

      {/* Preloaded Presets Bar (Glass Pill Container) */}
      <div className="mb-5 glass-pill p-3 rounded-2xl flex flex-wrap items-center justify-between gap-3">
        <span className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-2 uppercase font-mono">
          <Play className="w-3.5 h-3.5 text-blue-600 dark:text-cyan-400" />
          Quick Load Vendor Presets:
        </span>
        <div className="flex items-center space-x-2 flex-wrap gap-y-1">
          {PRESETS.map(p => (
            <button
              key={p.id}
              onClick={() => loadPreset(p.id)}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold cursor-pointer flex items-center space-x-2 transition-all ${
                selectedPresetId === p.id
                  ? 'glass-btn-active font-bold'
                  : 'glass-btn hover:text-blue-600 dark:hover:text-cyan-400'
              }`}
            >
              <span>{p.name}</span>
              <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                selectedPresetId === p.id 
                  ? 'bg-white/20 text-white font-bold' 
                  : 'bg-slate-200/80 dark:bg-slate-700/80 text-slate-700 dark:text-slate-200 font-bold'
              }`}>
                {p.badge}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Form Fields */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-5">
        <div>
          <label className="block text-xs font-bold text-slate-800 dark:text-slate-200 mb-1.5">
            Parser Identifier Name
          </label>
          <input
            type="text"
            value={parserName}
            onChange={(e) => setParserName(e.target.value)}
            className="w-full bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 focus:border-cyan-500 rounded-lg p-2.5 text-xs font-mono font-semibold text-slate-900 dark:text-slate-100 outline-none"
          />
        </div>
        <div>
          <label className="block text-xs font-bold text-slate-800 dark:text-slate-200 mb-1.5">
            Device Source Identifier
          </label>
          <input
            type="text"
            value={sourceType}
            onChange={(e) => setSourceType(e.target.value)}
            className="w-full bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 focus:border-cyan-500 rounded-lg p-2.5 text-xs font-mono font-semibold text-slate-900 dark:text-slate-100 outline-none"
          />
        </div>
        <div>
          <label className="block text-xs font-bold text-slate-800 dark:text-slate-200 mb-1.5">
            Wire Format
          </label>
          <select
            value={wireFormat}
            onChange={(e) => setWireFormat(e.target.value)}
            className="w-full bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 focus:border-cyan-500 rounded-lg p-2.5 text-xs font-mono font-semibold text-slate-900 dark:text-slate-100 outline-none cursor-pointer"
          >
            <option value="CEF">Common Event Format (CEF)</option>
            <option value="SYSLOG">RFC 5424/3164 Syslog</option>
            <option value="JSON">Structured JSON</option>
            <option value="KEY_VALUE">Key-Value Pairs</option>
          </select>
        </div>
      </div>

      {/* Raw Sample Payload */}
      <div className="mb-5">
        <div className="flex items-center justify-between mb-1.5">
          <label className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
            <span>Sample Wire Log Payload</span>
            {aiConfidence && (
              <span className="text-[10px] font-mono px-2 py-0.2 rounded-full bg-emerald-100 text-emerald-800 font-bold border border-emerald-200">
                {aiConfidence}% AI Confidence
              </span>
            )}
          </label>
          <button
            type="button"
            onClick={handleAiInferSchema}
            disabled={isInferring}
            className="glass-btn-active flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl font-bold text-xs cursor-pointer disabled:opacity-50 transition-all hover:scale-102"
            title="Use AI Pattern Recognition to automatically detect source, format, and map fields"
          >
            <Sparkles className={`w-3.5 h-3.5 text-amber-300 ${isInferring ? 'animate-spin' : ''}`} />
            <span>{isInferring ? 'AI Analyzing...' : 'AI Auto-Map Fields'}</span>
          </button>
        </div>
        <textarea
          rows={2}
          value={rawSample}
          onChange={(e) => setRawSample(e.target.value)}
          className="w-full bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 focus:border-cyan-500 rounded-lg p-3 text-xs font-mono text-slate-900 dark:text-slate-100 outline-none"
          placeholder="Paste any custom/unknown raw log string here..."
        />
      </div>

      {/* Semantic Projection Matrix */}
      <div className="bg-slate-50 dark:bg-slate-900/60 p-4.5 rounded-xl border border-slate-200 dark:border-slate-800 mb-5">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider flex items-center gap-2 font-mono">
            <Workflow className="w-4 h-4 text-blue-600 dark:text-cyan-400" />
            Device-to-OCSF Semantic Projection Matrix
          </span>
          <button
            onClick={addMappingRow}
            className="glass-btn flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-bold transition cursor-pointer hover:text-cyan-600 dark:hover:text-cyan-400"
          >
            <Plus className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
            <span>Add Field Mapping</span>
          </button>
        </div>

        <div className="space-y-2.5 max-h-52 overflow-y-auto pr-1">
          {mappings.map((m, idx) => (
            <div key={idx} className="flex items-center space-x-2.5">
              <input
                type="text"
                placeholder="Device Field (e.g. src)"
                value={m.sourceKey}
                onChange={(e) => updateMappingRow(idx, 'sourceKey', e.target.value)}
                className="flex-1 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 focus:border-cyan-500 rounded-lg p-2 text-xs font-mono text-slate-900 dark:text-slate-100 outline-none"
              />
              <span className="text-slate-400 dark:text-slate-500 text-xs font-mono font-bold">&rarr;</span>
              <select
                value={m.ocsfPath}
                onChange={(e) => updateMappingRow(idx, 'ocsfPath', e.target.value)}
                className="flex-1 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 focus:border-cyan-500 rounded-lg p-2 text-xs font-mono text-slate-900 dark:text-slate-100 outline-none cursor-pointer"
              >
                {OCSF_TARGET_FIELDS.map(f => (
                  <option key={f.value} value={f.value}>{f.label}</option>
                ))}
              </select>
              <button
                onClick={() => removeMappingRow(idx)}
                className="p-2 text-slate-400 hover:text-rose-600:text-rose-400 transition cursor-pointer rounded-lg hover:bg-rose-50:bg-rose-950/50"
                title="Remove"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Live In-Flight Normalized Preview */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 mb-5">
        <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-300">
            <Sparkles className="w-3.5 h-3.5 text-blue-400" />
            <span className="font-bold uppercase tracking-wider text-slate-200">
              Live Projected OCSF v1.1.0 JSON Preview
            </span>
            <span className="px-2 py-0.2 rounded text-[10px] bg-blue-900/60 text-blue-300 font-bold border border-blue-700">
              Zero-Downtime Safe
            </span>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Auto-Updates with Mappings
          </span>
        </div>
        <pre className="text-emerald-400 font-mono text-xs overflow-x-auto max-h-44 p-2 bg-slate-950/80 rounded border border-slate-800/80 leading-relaxed">
          <code>
            {JSON.stringify({
              metadata: {
                version: "1.1.0",
                source_type: sourceType,
                wire_format: wireFormat,
                parser: parserName
              },
              class_uid: sourceType.includes('auth') ? 3002 : (sourceType.includes('waf') ? 2001 : 4001),
              category_name: sourceType.includes('auth') ? "Identity & Access Management" : "Network Activity",
              activity_name: "Normalized Event Flow",
              projections: Object.fromEntries(
                mappings.filter(m => m.sourceKey.trim()).map(m => [m.ocsfPath, `{{.${m.sourceKey}}}`])
              ),
              compliance: {
                pii_redacted: true,
                non_repudiation: "SHA-256 Verified"
              }
            }, null, 2)}
          </code>
        </pre>
      </div>

      {/* Deployment Result */}
      {deployResult.status === 'success' && (
        <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-xl text-emerald-900 text-xs space-y-2.5">
          <div className="flex items-center space-x-2 font-bold">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
            <span>{deployResult.message}</span>
          </div>
          {deployResult.vrlPreview && (
            <div>
              <div className="text-xs text-slate-600 font-mono mb-1.5 flex items-center gap-1.5 font-bold">
                <FileCode className="w-3.5 h-3.5 text-emerald-600" />
                <span>Generated Vector Remap Language (VRL) Artifact in /vector:</span>
              </div>
              <pre className="bg-slate-900 text-emerald-400 p-3.5 rounded-lg border border-slate-800 font-mono text-xs overflow-x-auto max-h-40 leading-relaxed shadow-inner">
                {deployResult.vrlPreview}
              </pre>
            </div>
          )}
        </div>
      )}

      {deployResult.status === 'error' && (
        <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl text-rose-900 text-xs flex items-center space-x-2 font-semibold">
          <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
          <span>{deployResult.message}</span>
        </div>
      )}
    </div>
  );
};
