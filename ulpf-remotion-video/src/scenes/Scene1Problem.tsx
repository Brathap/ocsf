import React from 'react';
import { interpolate, useCurrentFrame, spring, useVideoConfig } from 'remotion';
import { GlassCard } from '../components/GlassCard';
import { GlowBadge } from '../components/GlowBadge';
import { THEME } from '../styles/theme';

export const Scene1Problem: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const titleProgress = spring({ frame, fps, config: { damping: 14 } });
  const titleOpacity = interpolate(frame, [0, 20], [0, 1]);
  const glitchOffset = Math.sin(frame * 0.8) * (frame % 15 === 0 ? 8 : 0);

  const rawLogs = [
    '<34>1 2026-09-29T07:12:00Z gw01.nic.in kernel: [UFW BLOCK] SRC=198.51.100.23 DST=10.0.4.12 PROTO=TCP',
    'W3C-IIS 2026-09-29 07:12:01 POST /api/v1/auth - 200 user="rajesh.kumar" aadhaar="9182-3746-1928"',
    'CEF:0|PaloAlto|PAN-OS|10.1|THREAT|vulnerability|10|src=203.0.113.88 msg="Log4j JNDI Exploit Attempt"',
    'SYSLOG-NG: alert: kernel heap spray detected pid=4129 comm="mal_inject"',
  ];

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        width: '100%',
        height: '100%',
        padding: '80px',
        boxSizing: 'border-box',
        transform: `translateY(${(1 - titleProgress) * 40}px)`,
        opacity: titleOpacity,
      }}
    >
      <div style={{ marginBottom: '24px' }}>
        <GlowBadge label="CRITICAL VULNERABILITY // AIR-GAP SILOS" variant="rose" />
      </div>

      <h1
        style={{
          fontSize: '64px',
          fontWeight: 800,
          textAlign: 'center',
          maxWidth: '1200px',
          lineHeight: 1.15,
          margin: '0 0 20px 0',
          transform: `translateX(${glitchOffset}px)`,
        }}
      >
        Enterprise Telemetry Is{' '}
        <span style={{ color: THEME.rose, textShadow: '0 0 30px rgba(244, 63, 94, 0.6)' }}>
          Fractured & Unprotected
        </span>
      </h1>

      <p
        style={{
          fontSize: '22px',
          color: '#94a3b8',
          textAlign: 'center',
          maxWidth: '850px',
          margin: '0 0 45px 0',
        }}
      >
        Proprietary formats, exposed citizen Aadhaar IDs, and zero cryptographic auditability leave air-gapped critical infrastructure exposed.
      </p>

      {/* Chaotic Logs Stream */}
      <GlassCard style={{ width: '1000px', padding: '24px 30px' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {rawLogs.map((log, index) => {
            const rowOpacity = interpolate(frame, [15 + index * 10, 35 + index * 10], [0, 1], {
              extrapolateLeft: 'clamp',
              extrapolateRight: 'clamp',
            });
            const hasAadhaar = log.includes('aadhaar');

            return (
              <div
                key={index}
                style={{
                  fontFamily: THEME.fonts.mono,
                  fontSize: '15px',
                  color: hasAadhaar ? THEME.rose : '#cbd5e1',
                  backgroundColor: hasAadhaar ? 'rgba(244, 63, 94, 0.1)' : 'rgba(15, 23, 42, 0.5)',
                  padding: '12px 18px',
                  borderRadius: '12px',
                  border: `1px solid ${hasAadhaar ? 'rgba(244, 63, 94, 0.4)' : 'rgba(255, 255, 255, 0.05)'}`,
                  opacity: rowOpacity,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <span>{log}</span>
                {hasAadhaar && (
                  <span
                    style={{
                      fontSize: '11px',
                      backgroundColor: THEME.rose,
                      color: '#ffffff',
                      fontWeight: 700,
                      padding: '4px 8px',
                      borderRadius: '6px',
                    }}
                  >
                    EXPOSED PII DETECTED
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </GlassCard>
    </div>
  );
};
