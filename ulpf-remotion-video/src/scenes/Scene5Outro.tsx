import React from 'react';
import { interpolate, useCurrentFrame, spring, useVideoConfig } from 'remotion';
import { ULPFLogo } from '../assets/ULPFLogo';
import { GlowBadge } from '../components/GlowBadge';
import { THEME } from '../styles/theme';

export const Scene5Outro: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const logoScale = spring({ frame, fps, config: { damping: 10 } });
  const textOpacity = interpolate(frame, [15, 35], [0, 1], { extrapolateRight: 'clamp' });

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        width: '100%',
        height: '100%',
        boxSizing: 'border-box',
      }}
    >
      <div style={{ transform: `scale(${logoScale})`, marginBottom: '28px' }}>
        <ULPFLogo size={130} />
      </div>

      <div style={{ opacity: textOpacity, textAlign: 'center' }}>
        <div style={{ marginBottom: '16px' }}>
          <GlowBadge label="SMART INDIA HACKATHON 2024 · PROBLEM STATEMENT #26156" variant="cyan" />
        </div>

        <h1
          style={{
            fontSize: '72px',
            fontWeight: 900,
            letterSpacing: '-0.02em',
            margin: '0 0 16px 0',
          }}
        >
          ULPF SENTINEL
        </h1>

        <p
          style={{
            fontSize: '24px',
            color: '#94a3b8',
            maxWidth: '900px',
            lineHeight: 1.5,
            margin: '0 0 36px 0',
          }}
        >
          Unified Log Processing Framework for Air-Gapped Critical Infrastructure.
          Zero Trust. Tamper-Proof. Production Ready.
        </p>

        {/* Feature Pills */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: '16px' }}>
          {['100% OCSF v1.1.0 Compliant', 'Verhoeff PII Scrubber', 'RFC 6962 Merkle Ledger', 'Sub-Millisecond Vector Ingest'].map(
            (feat, i) => (
              <span
                key={i}
                style={{
                  padding: '8px 18px',
                  borderRadius: '9999px',
                  backgroundColor: 'rgba(255, 255, 255, 0.05)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  fontSize: '13px',
                  fontFamily: THEME.fonts.mono,
                  color: '#cbd5e1',
                }}
              >
                {feat}
              </span>
            )
          )}
        </div>
      </div>
    </div>
  );
};
