import React from 'react';
import { interpolate, useCurrentFrame, spring, useVideoConfig } from 'remotion';
import { GlassCard } from '../components/GlassCard';
import { GlowBadge } from '../components/GlowBadge';
import { ULPFLogo } from '../assets/ULPFLogo';
import { THEME } from '../styles/theme';

export const Scene2Transformation: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const scanX = interpolate(frame, [0, 180], [0, 100], { extrapolateRight: 'clamp' });
  const pulse = Math.sin(frame * 0.15) * 6;
  const piiRedactedProgress = interpolate(frame, [40, 80], [0, 1], { extrapolateRight: 'clamp' });

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        width: '100%',
        height: '100%',
        padding: '60px 80px',
        boxSizing: 'border-box',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '20px' }}>
        <ULPFLogo size={60} />
        <GlowBadge label="REAL-TIME INGESTION ENGINE · OCSF v1.1.0" variant="cyan" />
      </div>

      <h2
        style={{
          fontSize: '56px',
          fontWeight: 800,
          textAlign: 'center',
          margin: '0 0 16px 0',
        }}
      >
        Autonomous Ingestion &{' '}
        <span style={{ color: THEME.cyan, textShadow: '0 0 30px rgba(6, 182, 212, 0.6)' }}>
          Verhoeff Cryptographic Redaction
        </span>
      </h2>

      <p style={{ fontSize: '20px', color: '#94a3b8', margin: '0 0 40px 0' }}>
        Heterogeneous logs instantly mapped into standardized OCSF classes with zero packet drops.
      </p>

      {/* Before / After Pipeline Split */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '30px', width: '1280px' }}>
        {/* Left: Raw Dirty Log */}
        <GlassCard style={{ flex: 1, height: '360px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '16px' }}>
            <span style={{ fontFamily: THEME.fonts.mono, fontSize: '13px', color: '#94a3b8' }}>
              RAW INGESTION BUFFER
            </span>
            <span style={{ fontSize: '12px', color: THEME.rose, fontWeight: 700 }}>UNSTRUCTURED</span>
          </div>

          <pre
            style={{
              fontFamily: THEME.fonts.mono,
              fontSize: '14px',
              lineHeight: 1.6,
              color: '#cbd5e1',
              whiteSpace: 'pre-wrap',
            }}
          >
            {`timestamp: 2026-09-29T07:15:30.104Z
source_ip: 172.16.20.55
target_ip: 198.51.100.10
message: "User logged in with national citizen id: `}
            <span
              style={{
                backgroundColor: piiRedactedProgress > 0.5 ? 'transparent' : 'rgba(244, 63, 94, 0.3)',
                color: piiRedactedProgress > 0.5 ? THEME.cyan : THEME.rose,
                fontWeight: 'bold',
                padding: '2px 4px',
                borderRadius: '4px',
              }}
            >
              {piiRedactedProgress > 0.5 ? '[REDACTED_AADHAAR]' : '9182-3746-1928'}
            </span>
            {`"\nstatus: 200 OK`}
          </pre>
        </GlassCard>

        {/* Center: Laser Scanning Divider */}
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            position: 'relative',
          }}
        >
          <div
            style={{
              width: '4px',
              height: '320px',
              background: `linear-gradient(to bottom, transparent, ${THEME.cyan}, transparent)`,
              boxShadow: `0 0 20px ${THEME.cyan}`,
            }}
          />
          <span
            style={{
              position: 'absolute',
              backgroundColor: THEME.cyan,
              color: '#000',
              fontWeight: 900,
              fontSize: '11px',
              padding: '6px 12px',
              borderRadius: '9999px',
              fontFamily: THEME.fonts.mono,
              boxShadow: '0 0 15px rgba(6, 182, 212, 0.8)',
            }}
          >
            VERHOEFF PASS
          </span>
        </div>

        {/* Right: Normalized OCSF 1.1.0 JSON */}
        <GlassCard style={{ flex: 1, height: '360px', borderColor: 'rgba(6, 182, 212, 0.3)' }} glow>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '16px' }}>
            <span style={{ fontFamily: THEME.fonts.mono, fontSize: '13px', color: THEME.cyan }}>
              OCSF v1.1.0 NORMALIZED JSON
            </span>
            <span style={{ fontSize: '12px', color: THEME.emerald, fontWeight: 700 }}>VERIFIED</span>
          </div>

          <pre
            style={{
              fontFamily: THEME.fonts.mono,
              fontSize: '13px',
              lineHeight: 1.5,
              color: '#38bdf8',
              whiteSpace: 'pre-wrap',
            }}
          >
            {`{
  "class_uid": 3002,
  "category_name": "Audit Activity",
  "activity_name": "Logon Success",
  "src_endpoint": { "ip": "172.16.20.55" },
  "dst_endpoint": { "ip": "198.51.100.10" },
  "compliance": {
    "pii_redacted": true,
    "verhoeff_valid": true
  }
}`}
          </pre>
        </GlassCard>
      </div>
    </div>
  );
};
