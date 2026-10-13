export interface Traceability {
  raw_sha256: string;
  raw_base64: string;
  ingest_timestamp: string;
  sanitized_raw: string;
}

export interface Endpoint {
  ip: string;
  port?: number;
  geo?: string;
}

export interface ThreatEnrichment {
  is_malicious: boolean;
  threat_actor: string;
  threat_level: string;
  confidence?: number;
  mitre_id?: string;
}

export interface Compliance {
  pii_redacted: boolean;
  standard: string;
  redacted_tokens?: string[];
}

export interface OcsfData {
  metadata: {
    version: string;
    product: {
      vendor_name: string;
      name: string;
    };
    source_type?: string;
    wire_format?: string;
  };
  class_uid: number;
  category_name: string;
  activity_name: string;
  severity_id: number;
  severity: string;
  src_endpoint: Endpoint;
  dst_endpoint: Endpoint;
  enrichment: ThreatEnrichment;
  compliance: Compliance;
}

export interface ULPFLogRecord {
  id?: string;
  is_simulated?: boolean;
  traceability: Traceability;
  normalized_data: OcsfData;
}
