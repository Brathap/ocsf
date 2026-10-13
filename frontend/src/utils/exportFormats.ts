export interface FormatExportOptions {
  filename?: string;
  format: 'json' | 'jsonl' | 'csv' | 'cef' | 'syslog' | 'jsonl.gz' | 'compact_json' | 'csv.gz';
}

/**
 * Convert a single ULPFLogRecord or its normalized data into standard CEF string
 */
export function recordToCef(record: any): string {
  const norm = record?.normalized_data || {};
  const trace = record?.traceability || {};
  const escapeCef = (str: string) => String(str).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
  const vendor = escapeCef(norm?.metadata?.product?.vendor_name || 'ULPF');
  const product = escapeCef(norm?.metadata?.product?.name || 'Pipeline');
  const version = escapeCef(norm?.metadata?.product?.version || norm?.metadata?.version || '1.1.0');
  const classUid = escapeCef(norm?.class_uid || '4001');
  const name = escapeCef(norm?.activity_name || 'Security Event');
  const severity = norm?.severity_id || (norm?.severity === 'Critical' ? 10 : norm?.severity === 'High' ? 7 : 3);

  const extensions: string[] = [];
  if (norm?.src_endpoint?.ip) extensions.push(`src=${norm.src_endpoint.ip}`);
  if (norm?.src_endpoint?.port) extensions.push(`spt=${norm.src_endpoint.port}`);
  if (norm?.dst_endpoint?.ip) extensions.push(`dst=${norm.dst_endpoint.ip}`);
  if (norm?.dst_endpoint?.port) extensions.push(`dpt=${norm.dst_endpoint.port}`);
  if (norm?.actor?.user?.name) extensions.push(`suser=${escapeCef(norm.actor.user.name)}`);
  if (norm?.category_name) extensions.push(`cat=${escapeCef(norm.category_name)}`);
  if (trace?.raw_sha256) extensions.push(`cs1Label=SHA256 cs1=${trace.raw_sha256}`);
  if (trace?.sanitized_raw) {
    const cleanRaw = trace.sanitized_raw.replace(/[\n\r]/g, ' ').replace(/=/g, '\\=').substring(0, 160);
    extensions.push(`msg=${cleanRaw}`);
  }

  return `CEF:0|${vendor}|${product}|${version}|${classUid}|${name}|${severity}|${extensions.join(' ')}`;
}

/**
 * Convert a record into RFC5424 / RFC3164 Syslog format
 */
export function recordToSyslog(record: any): string {
  const norm = record?.normalized_data || {};
  const trace = record?.traceability || {};
  const isoTime = trace?.ingest_timestamp || new Date().toISOString();
  const host = (norm?.metadata?.product?.name || 'ulpf-edge-sensor').replace(/[^a-zA-Z0-9_-]/g, '-');
  const app = norm?.metadata?.source_type || 'ulpf-core';
  const msg = trace?.sanitized_raw || JSON.stringify(norm);
  const pri = norm?.severity === 'Critical' ? 131 : norm?.severity === 'High' ? 132 : 134; // Local0 facility

  return `<${pri}>1 ${isoTime} ${host} ${app} - - [ocsf@4001 class_uid="${norm.class_uid || 4001}"] ${msg}`;
}

/**
 * Convert an array of records to tabular CSV
 */
export function recordsToCsv(records: any[]): string {
  const headers = [
    'Timestamp',
    'Class_UID',
    'Category',
    'Activity',
    'Severity',
    'Source_IP',
    'Source_Port',
    'Dest_IP',
    'Dest_Port',
    'Actor_User',
    'Threat_Actor',
    'PII_Scrubbed',
    'SHA256_Hash',
    'Raw_Payload'
  ];

  const rows = records.map(r => {
    const norm = r?.normalized_data || {};
    const trace = r?.traceability || {};
    const piiRedacted = Boolean(norm?.compliance?.pii_redacted || (trace?.redacted_payload && trace.redacted_payload.includes('[REDACTED_AADHAAR]')));

    const sanitizeCsvCell = (val: any): string => {
      let str = String(val ?? '');
      if (/^[=+\-@\t\r]/.test(str)) {
        str = "'" + str;
      }
      return str.replace(/"/g, '""').replace(/[\r\n]+/g, ' ');
    };

    const fields = [
      sanitizeCsvCell(trace?.ingest_timestamp),
      sanitizeCsvCell(norm?.class_uid || '4001'),
      sanitizeCsvCell(norm?.category_name),
      sanitizeCsvCell(norm?.activity_name),
      sanitizeCsvCell(norm?.severity || 'Informational'),
      sanitizeCsvCell(norm?.src_endpoint?.ip),
      sanitizeCsvCell(norm?.src_endpoint?.port),
      sanitizeCsvCell(norm?.dst_endpoint?.ip),
      sanitizeCsvCell(norm?.dst_endpoint?.port),
      sanitizeCsvCell(norm?.actor?.user?.name),
      sanitizeCsvCell(norm?.enrichment?.threat_actor || norm?.threat?.actor || 'None'),
      piiRedacted ? 'YES' : 'NO',
      sanitizeCsvCell(trace?.raw_sha256),
      sanitizeCsvCell(trace?.sanitized_raw)
    ];

    return fields.map(f => `"${f}"`).join(',');
  });

  return [headers.join(','), ...rows].join('\n');
}

/**
 * Universal file trigger
 */
export function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

/**
 * Strips verbose repeated envelope fields to produce an ultra-compact OCSF telemetry record
 * Retains exact timestamp, class, activity, endpoints, severity, and forensic raw_sha256 hash
 */
export function recordToCompactOcsf(record: any): any {
  const norm = record?.normalized_data || {};
  const trace = record?.traceability || {};
  return {
    time: trace?.ingest_timestamp || new Date().toISOString(),
    class_uid: norm?.class_uid || 4001,
    activity: norm?.activity_name || 'event',
    severity: norm?.severity || 'Informational',
    src: norm?.src_endpoint?.port ? `${norm.src_endpoint.ip}:${norm.src_endpoint.port}` : norm?.src_endpoint?.ip,
    dst: norm?.dst_endpoint?.port ? `${norm.dst_endpoint.ip}:${norm.dst_endpoint.port}` : norm?.dst_endpoint?.ip,
    actor: norm?.actor?.user?.name || norm?.threat?.actor,
    pii: norm?.compliance?.pii_redacted ? true : undefined,
    sha256: trace?.raw_sha256
  };
}

/**
 * Universal binary / compressed blob download trigger
 */
export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Compress content string using browser native CompressionStream ('gzip')
 */
export async function compressAndDownload(content: string, filename: string, mimeType = 'application/gzip') {
  if (typeof CompressionStream !== 'undefined') {
    try {
      const stream = new Blob([content]).stream().pipeThrough(new CompressionStream('gzip'));
      const compressedBlob = await new Response(stream).blob();
      downloadBlob(compressedBlob, filename);
      return;
    } catch {
      // Fallback to uncompressed if CompressionStream errors
    }
  }
  downloadFile(content, filename.replace(/\.gz$/, ''), 'text/plain;charset=utf-8;');
}

/**
 * Multi-format exporter for single or batched logs with zero-bloat compression
 */
export async function exportLogs(
  records: any[], 
  format: 'json' | 'jsonl' | 'csv' | 'cef' | 'syslog' | 'jsonl.gz' | 'compact_json' | 'csv.gz', 
  baseFilename = 'ulpf_export'
) {
  const count = records.length;
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

  if (format === 'jsonl.gz' || format === 'jsonl') {
    // Both standard JSONL and jsonl.gz are compressed to ensure zero raw bloat
    const filename = `${baseFilename}_${count}records_${timestamp}.jsonl.gz`;
    const payload = records.map(r => JSON.stringify(r)).join('\n');
    await compressAndDownload(payload, filename, 'application/gzip');
  } else if (format === 'csv.gz' || format === 'csv') {
    // Both CSV and csv.gz are compressed with Gzip
    const filename = `${baseFilename}_${count}records_${timestamp}.csv.gz`;
    const payload = recordsToCsv(records);
    await compressAndDownload(payload, filename, 'application/gzip');
  } else if (format === 'compact_json') {
    // Ultra-Compact OCSF JSON also gzipped for maximum reduction
    const filename = `${baseFilename}_${count}records_compact_${timestamp}.json.gz`;
    const compactRecords = records.map(recordToCompactOcsf);
    const payload = JSON.stringify(compactRecords, null, 2);
    await compressAndDownload(payload, filename, 'application/gzip');
  } else if (format === 'json') {
    // Full OCSF JSON compressed
    const filename = `${baseFilename}_${count}records_${timestamp}.json.gz`;
    const payload = JSON.stringify(records, null, 2);
    await compressAndDownload(payload, filename, 'application/gzip');
  } else if (format === 'cef') {
    // CEF ArcSight logs compressed
    const filename = `${baseFilename}_${count}records_${timestamp}.cef.gz`;
    const payload = records.map(recordToCef).join('\n');
    await compressAndDownload(payload, filename, 'application/gzip');
  } else if (format === 'syslog') {
    // RFC5424 Syslog compressed
    const filename = `${baseFilename}_${count}records_${timestamp}.log.gz`;
    const payload = records.map(recordToSyslog).join('\n');
    await compressAndDownload(payload, filename, 'application/gzip');
  }
}
