import React from 'react';
import { interpolate, useCurrentFrame, spring, useVideoConfig } from 'remotion';
import { GlassCard } from '../components/GlassCard';
import { GlowBadge } from '../components/GlowBadge';
import { THEME } from '../styles/theme';

export const Scene3MerkleTree: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const rootSpring = spring({ frame: frame - 40, fps, config: { damping: 12 } });

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
      <div style={{ marginBottom: '20px' }}>
        <GlowBadge label="CRYPTOGRAPHIC AUDIT LEDGER · RFC 6962" variant="emerald" />
      </div>

      <h2
        style={{
          fontSize: '56px',
          fontWeight: 800,
          textAlign: 'center',
          margin: '0 0 16px 0',
        }}
      >
        Immutable{' '}
        <span style={{ color: THEME.emerald, textShadow: '0 0 30px rgba(16, 185, 129, 0.6)' }}>
          Merkle Tree Provenance
        </span>
      </h2>

      <p style={{ fontSize: '20px', color: '#94a3b8', margin: '0 0 45px 0' }}>
        Cryptographic zero-knowledge proofs guarantee non-repudiation and instantaneous tamper detection.
      </p>

      {/* Merkle Tree Visualization */}
      <GlassCard style={{ width: '920px', padding: '36px', textAlign: 'center' }}>
        {/* Root */}
        <div
          style={{
            display: 'inline-block',
            padding: '14px 28px',
            borderRadius: '16px',
            backgroundColor: 'rgba(16, 185, 129, 0.15)',
            border: `2px solid ${THEME.emerald}`,
            boxShadow: '0 0 25px rgba(16, 185, 129, 0.4)',
            transform: `scale(${Math.max(0, rootSpring)})`,
          }}
        >
          <span style={{ fontFamily: THEME.fonts.mono, fontSize: '13px', color: THEME.emerald, display: 'block', fontWeight: 700 }}>
            MERKLE ROOT (SHA-256)
          </span>
          <span style={{ fontFamily: THEME.fonts.mono, fontSize: '16px', color: '#f8fafc', fontWeight: 800 }}>
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
          </span>
        </div>

        {/* Tree Connectors */}
        <div style={{ margin: '20px 0', color: THEME.emerald, fontSize: '24px', opacity: 0.7 }}>
          ▲
        </div>

        {/* Level 1 Leaves */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: '30px' }}>
          {['Node 01: Hash(L1 + L2)', 'Node 02: Hash(L3 + L4)'].map((label, idx) => (
            <div
              key={idx}
              style={{
                flex: 1,
                padding: '12px 18px',
                borderRadius: '12px',
                backgroundColor: 'rgba(15, 23, 42, 0.8)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                fontFamily: THEME.fonts.mono,
                fontSize: '13px',
                color: '#cbd5e1',
              }}
            >
              {label}
            </div>
          ))}
        </div>

        {/* Base Raw Logs */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: '16px', marginTop: '20px' }}>
          {['Log 1: Auth Event', 'Log 2: Syslog Alert', 'Log 3: DNS Query', 'Log 4: Netflow Traffic'].map((leaf, idx) => (
            <div
              key={idx}
              style={{
                flex: 1,
                padding: '8px 12px',
                borderRadius: '8px',
                backgroundColor: 'rgba(6, 182, 212, 0.08)',
                border: '1px solid rgba(6, 182, 212, 0.2)',
                fontFamily: THEME.fonts.mono,
                fontSize: '11px',
                color: THEME.cyan,
              }}
            >
              {leaf}
            </div>
          ))}
        </div>
      </GlassCard>
    </div>
  );
};
