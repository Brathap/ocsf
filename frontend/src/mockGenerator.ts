import type { ULPFLogRecord } from './types';

const THREAT_ACTORS = [
  { ip: '198.51.100.23', actor: 'APT29 (Cozy Bear)', severity: 'Critical', geo: 'RU', mitreId: 'T1133' },
  { ip: '203.0.113.84', actor: 'Lazarus Group', severity: 'Critical', geo: 'KP', mitreId: 'T1110.001' },
  { ip: '192.0.2.145', actor: 'Sandworm (Unit 74455)', severity: 'High', geo: 'RU', mitreId: 'T1498' },
  { ip: '103.21.244.12', actor: 'Volt Typhoon', severity: 'Medium', geo: 'CN', mitreId: 'T1078' },
  { ip: '198.51.100.99', actor: 'LockBit 3.0', severity: 'High', geo: 'Tor/Darknet', mitreId: 'T1486' },
  { ip: '203.0.113.111', actor: 'Cobalt Strike C2', severity: 'Critical', geo: 'US-Proxy', mitreId: 'T1071.001' },
];

const INTERNAL_IPS = [
  { ip: '10.100.4.12', geo: 'HQ-VLAN-10' },
  { ip: '172.16.20.55', geo: 'SecOps-Cluster' },
  { ip: '192.168.1.105', geo: 'DMZ-Gateway' },
  { ip: '10.8.0.42', geo: 'VPN-Tunnel-In' },
  { ip: '172.20.100.15', geo: 'Core-Router-Gi0' },
];

const TARGETS = [
  { ip: '198.51.100.10', geo: 'Govt Portal Main' },
  { ip: '203.0.113.5', geo: 'Auth DC-01' },
  { ip: '10.0.0.1', geo: 'Core Switch 01' },
  { ip: '172.16.0.20', geo: 'Oracle DB Vault' },
];

const AADHAAR_SAMPLES = [
  '982345129081',
  '452178902341',
  '671234908123',
  '239012458712',
];

// Helper to fake demo hash for synthetic/mock records.
// WARNING: This is NOT SHA-256 and is NOT cryptographic. It is a 32-bit bit-shift murmur hash
// used strictly for simulated UI demonstration. It must never be presented or claimed as SHA-256.
function fakeDemoHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return hex.repeat(8).substring(0, 64);
}

export function generateSyntheticLog(forceLaptop?: boolean): ULPFLogRecord {
  // Demo Stream produces enterprise logs, or laptop logs if forceLaptop is true
  const isLaptopHost = Boolean(forceLaptop);
  const isMalicious = !isLaptopHost && Math.random() < 0.28;
  const hasAadhaar = !isLaptopHost && Math.random() < 0.32;
  const isCisco = !isLaptopHost && Math.random() < 0.5;
  const isImperva = !isLaptopHost && !isCisco && Math.random() < 0.6;

  const now = new Date();
  const timestamp = now.toISOString();

  let rawString = '';
  let sanitizedRaw = '';
  let srcIp = '';
  let srcGeo = '';
  let dstIp = '';
  let dstGeo = '';
  let ocsfClass = 4001;
  let categoryName = 'Network Activity';
  let activityName = 'Traffic Flow';
  let severity = 'Informational';
  let severityId = 1;
  let threatActor = 'None';
  let threatLevel = 'Benign';

  const target = TARGETS[Math.floor(Math.random() * TARGETS.length)];
  dstIp = target.ip;
  dstGeo = target.geo;

  let mitreId: string | undefined = undefined;

  if (isMalicious) {
    const threat = THREAT_ACTORS[Math.floor(Math.random() * THREAT_ACTORS.length)];
    srcIp = threat.ip;
    srcGeo = threat.geo;
    threatActor = threat.actor;
    threatLevel = threat.severity;
    mitreId = threat.mitreId;
    severity = threat.severity;
    severityId = threat.severity === 'Critical' ? 5 : 4;
  } else {
    const internal = INTERNAL_IPS[Math.floor(Math.random() * INTERNAL_IPS.length)];
    srcIp = internal.ip;
    srcGeo = internal.geo;
  }

  if (isCisco) {
    const action = isMalicious ? 'Denied' : 'Built';
    const sport = Math.floor(Math.random() * 50000) + 1024;
    const dport = [80, 443, 22, 3389, 53][Math.floor(Math.random() * 5)];
    rawString = `<164>${now.toDateString().slice(4, 10)} ${now.toLocaleTimeString()} ciscoasa: %ASA-4-106023: ${action} tcp src inside:${srcIp}/${sport} dst outside:${dstIp}/${dport} by access-group 'OUTSIDE_IN'`;
    sanitizedRaw = rawString;
    ocsfClass = 4001;
    categoryName = 'Network Activity';
    activityName = action === 'Denied' ? 'Firewall Drop (ACL)' : 'Connection Permitted';
    if (action === 'Denied' && !isMalicious) {
      severity = 'High';
      severityId = 4;
    }
  } else if (isImperva) {
    const act = isMalicious ? 'Blocked' : 'Passed';
    const sigId = isMalicious ? 'SQLI-001' : 'POLICY-OK';
    const sigName = isMalicious ? 'SQL Injection Attempt in Query Param' : 'Normal HTTP Request';
    rawString = `CEF:0|Imperva|SecureSphere|14.2|${sigId}|${sigName}|${isMalicious ? 8 : 2}|src=${srcIp} dst=${dstIp} spt=49201 dpt=443 act=${act} app=HTTPS request=/api/v1/auth/login`;
    sanitizedRaw = rawString;
    ocsfClass = 2001;
    categoryName = 'Security Finding';
    activityName = act === 'Blocked' ? 'WAF Exploit Blocked' : 'HTTP Traffic Passed';
    if (isMalicious) {
      severity = 'Critical';
      severityId = 5;
    }
  } else if (isLaptopHost) {
    const daemons = ['systemd', 'kernel', 'NetworkManager', 'pipewire', 'sshd', 'dbus-daemon'];
    const dName = daemons[Math.floor(Math.random() * daemons.length)];
    const pid = Math.floor(Math.random() * 4000) + 500;
    const actions = [
      'Started User Manager for UID 1000.',
      'wlan0: Link confirmed up and route configured.',
      'session-c1.scope: Deactivated successfully.',
      'CPU frequency scaling governor set to performance.',
      'IPC socket connection established from /run/user/1000/bus'
    ];
    const logMsg = actions[Math.floor(Math.random() * actions.length)];
    rawString = `[HOST:archlinux] ${now.toDateString().slice(4, 10)} ${now.toLocaleTimeString()} archlinux ${dName}[${pid}]: ${logMsg}`;
    sanitizedRaw = rawString;
    srcIp = '127.0.0.1';
    srcGeo = 'Laptop: archlinux';
    dstIp = '127.0.0.1';
    dstGeo = 'Local Host';
    ocsfClass = 1001;
    categoryName = 'Host System';
    activityName = `${dName}: System Routine`;
    severity = 'Informational';
    severityId = 1;
  } else {
    // Linux Auth / SSHD
    const user = ['root', 'admin', 'secops', 'svc_db', 'deployer'][Math.floor(Math.random() * 5)];
    const port = Math.floor(Math.random() * 30000) + 20000;
    const status = isMalicious ? 'Failed password' : 'Accepted publickey';
    const aadhaarNum = AADHAAR_SAMPLES[Math.floor(Math.random() * AADHAAR_SAMPLES.length)];
    const piiAddon = hasAadhaar ? ` session_id=SES_${Math.floor(Math.random() * 9000 + 1000)} gov_ref_aadhaar=${aadhaarNum}` : '';
    
    rawString = `<84>${now.toDateString().slice(4, 10)} ${now.toLocaleTimeString()} auth-server-01 sshd[${Math.floor(Math.random() * 40000 + 1000)}]: ${status} for ${user} from ${srcIp} port ${port} ssh2${piiAddon}`;
    
    sanitizedRaw = hasAadhaar 
      ? rawString.replace(new RegExp(`\\b${aadhaarNum}\\b`, 'g'), '[REDACTED_AADHAAR]')
      : rawString;

    ocsfClass = 3002;
    categoryName = 'Identity & Access Management';
    activityName = status.includes('Failed') ? 'Failed Authentication Attempt' : 'Privileged Session Started';
    if (status.includes('Failed') && !isMalicious) {
      severity = 'Medium';
      severityId = 3;
    }
  }

  const rawSha = fakeDemoHash(rawString + timestamp);
  const rawBase64 = typeof btoa !== 'undefined' ? btoa(rawString) : 'PDg0Pj0=';

  return {
    id: `log-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
    is_simulated: true,
    traceability: {
      raw_sha256: rawSha,
      raw_base64: rawBase64,
      ingest_timestamp: timestamp,
      sanitized_raw: sanitizedRaw,
    },
    normalized_data: {
      metadata: {
        version: '1.1.0',
        product: {
          vendor_name: isLaptopHost ? 'ULPF Host Agent' : 'ULPF Gateway',
          name: isLaptopHost ? 'Local Host Engine (archlinux)' : 'Enterprise Universal Parser',
        },
        source_type: isLaptopHost ? 'laptop_host' : isCisco ? 'cisco_asa' : isImperva ? 'imperva_waf' : 'linux_auth',
        wire_format: isLaptopHost ? 'SYSTEMD_JOURNAL' : isCisco ? 'SYSLOG' : isImperva ? 'CEF' : 'SYSLOG',
      },
      class_uid: ocsfClass,
      category_name: categoryName,
      activity_name: activityName,
      severity_id: severityId,
      severity: severity,
      src_endpoint: {
        ip: srcIp,
        port: 443,
        geo: srcGeo,
      },
      dst_endpoint: {
        ip: dstIp,
        port: 443,
        geo: dstGeo,
      },
      enrichment: {
        is_malicious: isMalicious,
        threat_actor: threatActor,
        threat_level: threatLevel,
        confidence: isMalicious ? 98.4 : 0,
        mitre_id: mitreId,
      },
      compliance: {
        pii_redacted: hasAadhaar,
        standard: 'OCSF-1.1.0',
        redacted_tokens: hasAadhaar ? ['[REDACTED_AADHAAR]'] : [],
      },
    },
  };
}
