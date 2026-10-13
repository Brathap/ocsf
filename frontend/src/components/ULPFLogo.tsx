import React from 'react';

interface LogoProps {
  className?: string;
  size?: number;
}

export const ULPFLogo: React.FC<LogoProps> = ({ className = '', size = 44 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`shrink-0 block ${className}`}
    >
      <defs>
        {/* Precision Beveled Cyber Gradient */}
        <linearGradient id="shieldMain" x1="12" y1="4" x2="52" y2="60" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#3b82f6" />
          <stop offset="45%" stopColor="#1d4ed8" />
          <stop offset="100%" stopColor="#0f172a" />
        </linearGradient>

        {/* Outer Tech Stroke Gradient */}
        <linearGradient id="borderGleam" x1="10" y1="4" x2="54" y2="58" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#60a5fa" />
          <stop offset="50%" stopColor="#38bdf8" />
          <stop offset="100%" stopColor="#1e3a8a" />
        </linearGradient>

        {/* Facet Light Accent Gradient */}
        <linearGradient id="facetHighlight" x1="32" y1="6" x2="54" y2="38" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#ffffff" stopOpacity="0.35" />
          <stop offset="100%" stopColor="#ffffff" stopOpacity="0.0" />
        </linearGradient>

        {/* Neon Cyan Laser Glow */}
        <filter id="neonBeamGlow" x="-30%" y="-30%" width="160%" height="160%">
          <feDropShadow dx="0" dy="0" stdDeviation="2.5" floodColor="#38bdf8" floodOpacity="0.85" />
        </filter>

        <filter id="coreGleam" x="-40%" y="-40%" width="180%" height="180%">
          <feDropShadow dx="0" dy="0" stdDeviation="3.5" floodColor="#60a5fa" floodOpacity="0.9" />
        </filter>
      </defs>

      {/* 1. Outer Angular Security Shield Silhouette */}
      <path
        d="M32 4L54 13V28C54 43 44 54 32 59C20 54 10 43 10 28V13L32 4Z"
        fill="#1e40af"
        stroke="#38bdf8"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      <path
        d="M32 4L54 13V28C54 43 44 54 32 59C20 54 10 43 10 28V13L32 4Z"
        fill="url(#shieldMain)"
        stroke="url(#borderGleam)"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />

      {/* 2. Prismatic 3D Right Facet for depth & sophistication */}
      <path
        d="M32 4L54 13V28C54 43 44 54 32 59V4Z"
        fill="url(#facetHighlight)"
      />

      {/* 3. Sleek Architectural Inset Lines (Air-Gap Armor Grid) */}
      <path
        d="M32 10L48 17.5V28C48 39.5 40.5 48.5 32 52.5C23.5 48.5 16 39.5 16 28V17.5L32 10Z"
        stroke="#1e3a8a"
        strokeWidth="1.2"
        strokeLinejoin="round"
      />

      {/* 4. Multi-Source Ingestion Streams (Converging into the pipeline) */}
      {/* Stream 1: Top Track */}
      <path
        d="M17 23H25L32 30H43"
        stroke="#38bdf8"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        filter="url(#neonBeamGlow)"
      />

      {/* Stream 2: Center Main High-Velocity Data Core */}
      <path
        d="M14 32H45"
        stroke="#ffffff"
        strokeWidth="3"
        strokeLinecap="round"
        filter="url(#coreGleam)"
      />

      {/* Stream 3: Bottom Track */}
      <path
        d="M17 41H25L32 34H43"
        stroke="#38bdf8"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        filter="url(#neonBeamGlow)"
      />

      {/* 5. Ingestion Port Terminals (Left) */}
      <circle cx="17" cy="23" r="1.8" fill="#38bdf8" />
      <circle cx="14" cy="32" r="2.2" fill="#ffffff" filter="url(#coreGleam)" />
      <circle cx="17" cy="41" r="1.8" fill="#38bdf8" />

      {/* 6. Central Quantum Diamond Core (Lossless Preservation Anchor) */}
      <polygon
        points="32,26 38,32 32,38 26,32"
        fill="#0284c7"
        stroke="#ffffff"
        strokeWidth="1.5"
        filter="url(#neonBeamGlow)"
      />
      <circle cx="32" cy="32" r="2.2" fill="#ffffff" />

      {/* 7. Output Standardized Pipeline Terminal (Right) */}
      <circle cx="45" cy="32" r="2.8" fill="#38bdf8" filter="url(#neonBeamGlow)" />
      <circle cx="45" cy="32" r="1.2" fill="#ffffff" />
    </svg>
  );
};
