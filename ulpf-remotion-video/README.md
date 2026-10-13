# ULPF Sentinel - Remotion Video Showcase

This package contains the complete, production-ready Remotion project for generating the **30-second 1080p 60/30fps** cinematic product demo of **ULPF Sentinel** (Air-Gapped Telemetry & OCSF Normalization Fabric).

## Structure
- `src/Root.tsx`: Remotion composition entrypoint (`ULPFSentinelDemo`, 1920x1080, 900 frames, 30fps).
- `src/ULPFSentinelVideo.tsx`: Master timeline with sequenced transitions.
- `src/scenes/`:
  - `Scene1Problem.tsx`: Shows fragmented, proprietary logs with exposed Aadhaar PII warnings.
  - `Scene2Transformation.tsx`: Laser scan pipeline demonstrating real-time OCSF normalization and Verhoeff redaction.
  - `Scene3MerkleTree.tsx`: Visualized RFC 6962 cryptographic hash tree with root ledger verification.
  - `Scene4Dashboard.tsx`: High-speed real-time velocity counters and live streaming SOC grid.
  - `Scene5Outro.tsx`: Branding shield animation and feature breakdown for SIH #26156.
- `src/assets/ULPFLogo.tsx`: Scalable vector emblem with dynamic cyan glow.
- `src/styles/theme.ts`: Unified cyber dark-mode palette & tokens.

## Running Locally

1. Install dependencies:
   ```bash
   npm install
   ```

2. Open the real-time browser preview studio:
   ```bash
   npm run preview
   ```

3. Render the production MP4 video:
   ```bash
   npm run build
   ```
