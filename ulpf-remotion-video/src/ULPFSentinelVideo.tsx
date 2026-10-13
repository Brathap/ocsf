import React from 'react';
import { AbsoluteFill, Sequence } from 'remotion';
import { Scene1Problem } from './scenes/Scene1Problem';
import { Scene2Transformation } from './scenes/Scene2Transformation';
import { Scene3MerkleTree } from './scenes/Scene3MerkleTree';
import { Scene4Dashboard } from './scenes/Scene4Dashboard';
import { Scene5Outro } from './scenes/Scene5Outro';
import { THEME } from './styles/theme';

export const ULPFSentinelVideo: React.FC = () => {
  return (
    <AbsoluteFill
      style={{
        backgroundColor: THEME.bg,
        color: '#f8fafc',
        fontFamily: THEME.fonts.sans,
        overflow: 'hidden',
      }}
    >
      {/* Background Subtle Cyber Glow */}
      <div
        style={{
          position: 'absolute',
          top: '-15%',
          left: '30%',
          width: '700px',
          height: '700px',
          borderRadius: '9999px',
          background: 'radial-gradient(circle, rgba(6, 182, 212, 0.12) 0%, transparent 70%)',
          filter: 'blur(80px)',
          pointerEvents: 'none',
        }}
      />
      <div
        style={{
          position: 'absolute',
          bottom: '-15%',
          right: '20%',
          width: '600px',
          height: '600px',
          borderRadius: '9999px',
          background: 'radial-gradient(circle, rgba(59, 130, 246, 0.1) 0%, transparent 70%)',
          filter: 'blur(80px)',
          pointerEvents: 'none',
        }}
      />

      {/* Scene 1: The Problem (0s - 5s) */}
      <Sequence from={0} durationInFrames={150}>
        <Scene1Problem />
      </Sequence>

      {/* Scene 2: Laser Normalization & PII Scrubbing (5s - 12s) */}
      <Sequence from={150} durationInFrames={210}>
        <Scene2Transformation />
      </Sequence>

      {/* Scene 3: Merkle Audit Ledger (12s - 18s) */}
      <Sequence from={360} durationInFrames={180}>
        <Scene3MerkleTree />
      </Sequence>

      {/* Scene 4: Live Floating Dashboard Preview (18s - 25s) */}
      <Sequence from={540} durationInFrames={210}>
        <Scene4Dashboard />
      </Sequence>

      {/* Scene 5: Outro & SIH #26156 Summary (25s - 30s) */}
      <Sequence from={750} durationInFrames={150}>
        <Scene5Outro />
      </Sequence>
    </AbsoluteFill>
  );
};
