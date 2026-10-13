import React from 'react';
import { interpolate, useCurrentFrame, useVideoConfig } from 'remotion';
import { GlassCard } from '../components/GlassCard';
import { GlowBadge } from '../components/GlowBadge';
import { THEME } from '../styles/theme';

export const Scene4Dashboard: React.FC = () => {
  const frame = useCurrentFrame();

  const epsCounter = Math.floor(interpolate(frame, [0, 90], [140, 2480], { extrapolateRight: 'clamp' }));

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        width: '100%',
        height: '100%',
        padding: '50px 80px',
        boxSizing: 'border-box',
      }}
    >
      <div style={{ marginBottom: '16px' }}>
        <GlowBadge label="HIGH-THROUGHPUT REAL-TIME SOC SUITE" variant="cyan" />
      </div>

      <h2
        style={{
          fontSize: '54px',
          fontWeight: 800,
          textAlign: 'center',
          margin: '0 0 16px 0',
        }}
      >
        Enterprise Air-Gapped{' '}
        <span style={{ color: THEME.cyan, textShadow: '0 0 30px rgba(6, 182, 212, 0.6)' }}>
          Telemetry Command Center
        </span>
      </h2>

      {/* Mock Telemetry Dashboard Ribbon */}
      <div style={{ display: 'flex', gap: '20px', width: '1300px', marginBottom: '24px' }}>
        <GlassCard style={{ flex: 1, padding: '20px' }}>
          <span style={{ fontSize: '11px', color: '#94a3b8', fontFamily: THEME.fonts.mono }}>INGESTION VELOCITY</span>
          <div style={{ fontSize: '36px', fontWeight: 900, color: THEME.cyan, marginTop: '8px', fontFamily: THEME.fonts.mono }}>
            {epsCounter.toLocaleString()} <span style={{ fontSize: '16px', color: '#64748b' }}>EPS</span>
          </div>
        </GlassCard>

        <GlassCard style={{ flex: 1, padding: '20px' }}>
          <span style={{ fontSize: '11px', color: '#94a3b8', fontFamily: THEME.fonts.mono }}>THREATS MITIGATED</span>
          <div style={{ fontSize: '36px', fontWeight: 900, color: THEME.rose, marginTop: '8px', fontFamily: THEME.fonts.mono }}>
            47 <span style={{ fontSize: '16px', color: '#64748b' }}>ACTIVE</span>
          </div>
        </GlassCard>

        <GlassCard style={{ flex: 1, padding: '20px' }}>
          <span style={{ fontSize: '11px', color: '#94a3b8', fontFamily: THEME.fonts.mono }}>PII CITIZEN TOKENS</span>
          <div style={{ fontSize: '36px', fontWeight: 900, color: THEME.emerald, marginTop: '8px', fontFamily: THEME.fonts.mono }}>
            100% <span style={{ fontSize: '16px', color: '#64748b' }}>SCRUBBED</span>
          </div>
        </GlassCard>

        <GlassCard style={{ flex: 1, padding: '20px' }}>
          <span style={{ fontSize: '11px', color: '#94a3b8', fontFamily: THEME.fonts.mono }}>COMPLIANCE STANDARD</span>
          <div style={{ fontSize: '36px', fontWeight: 900, color: '#f8fafc', marginTop: '8px', fontFamily: THEME.fonts.mono }}>
            OCSF <span style={{ fontSize: '16px', color: THEME.cyan }}>v1.1.0</span>
          </div>
        </GlassCard>
      </div>

      {/* Mock Table Stream View */}
      <GlassCard style={{ width: '1300px', padding: '18px 24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '12px', fontFamily: THEME.fonts.mono, fontSize: '12px', color: '#94a3b8' }}>
          <span style={{ width: '25%' }}>TIMESTAMP / HASH</span>
          <span style={{ width: '25%' }}>OCSF CLASS</span>
          <span style={{ width: '25%' }}>SOURCE ENDPOINT</span>
          <span style={{ width: '25%', textAlign: 'right' }}>SECURITY STATUS</span>
        </div>

        {[
          { time: '07:18:22.410', hash: '17a5e0fc17...', cls: 'Security Finding (2001)', ip: '172.16.20.55', status: 'BENIGN' },
          { time: '07:18:22.102', hash: 'b94f1c9982...', cls: 'Authentication (3002)', ip: '198.51.100.10', status: 'AADHAAR SCRUBBED' },
          { time: '07:18:21.890', hash: 'fe831201ab...', cls: 'Network Activity (4001)', ip: '203.0.113.88', status: 'THREAT ISOLATED' },
        ].map((row, i) => (
          <div
            key={i}
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '12px 0',
              borderBottom: '1px solid rgba(255,255,255,0.05)',
              fontFamily: THEME.fonts.mono,
              fontSize: '13px',
              color: '#f8fafc',
            }}
          >
            <span style={{ width: '25%', color: '#94a3b8' }}>{row.time} <span style={{ color: THEME.cyan }}>{row.hash}</span></span>
            <span style={{ width: '25%', fontWeight: 700 }}>{row.cls}</span>
            <span style={{ width: '25%' }}>{row.ip}</span>
            <span
              style={{
                width: '25%',
                textAlign: 'right',
                color: row.status.includes('THREAT') ? THEME.rose : THEME.emerald,
                fontWeight: 800,
              }}
            >
              {row.status}
            </span>
          </div>
        ))}
      </GlassCard>
    </div>
  );
};
