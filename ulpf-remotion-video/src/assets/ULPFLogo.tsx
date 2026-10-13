import React from 'react';

export const ULPFLogo: React.FC<{ size?: number; className?: string }> = ({ size = 80, className = '' }) => (
  <svg 
    width={size} 
    height={size} 
    viewBox="0 0 64 64" 
    fill="none" 
    className={className}
    style={{ filter: 'drop-shadow(0 0 25px rgba(6, 182, 212, 0.6))' }}
  >
    <defs>
      <linearGradient id="shieldGrad" x1="12" y1="4" x2="52" y2="60" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="#38bdf8" />
        <stop offset="50%" stopColor="#0284c7" />
        <stop offset="100%" stopColor="#0f172a" />
      </linearGradient>
    </defs>
    <path 
      d="M32 4L54 13V28C54 43 44 54 32 59C20 54 10 43 10 28V13L32 4Z" 
      fill="url(#shieldGrad)" 
      stroke="#38bdf8" 
      strokeWidth="2.5" 
      strokeLinejoin="round"
    />
    <path d="M17 23H25L32 30H43" stroke="#38bdf8" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M14 32H45" stroke="#ffffff" strokeWidth="3" strokeLinecap="round" />
    <path d="M17 41H25L32 34H43" stroke="#38bdf8" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
    <polygon points="32,26 38,32 32,38 26,32" fill="#0284c7" stroke="#ffffff" strokeWidth="1.5" />
  </svg>
);
