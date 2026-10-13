import React from 'react';
import { THEME } from '../styles/theme';

export const GlowBadge: React.FC<{
  label: string;
  variant?: 'cyan' | 'emerald' | 'rose' | 'amber';
}> = ({ label, variant = 'cyan' }) => {
  const colorMap = {
    cyan: { bg: 'rgba(6, 182, 212, 0.15)', border: '#06b6d4', text: '#22d3ee' },
    emerald: { bg: 'rgba(16, 185, 129, 0.15)', border: '#10b981', text: '#34d399' },
    rose: { bg: 'rgba(244, 63, 94, 0.15)', border: '#f4395e', text: '#fb7185' },
    amber: { bg: 'rgba(245, 158, 11, 0.15)', border: '#f59e0b', text: '#fbbf24' },
  };

  const c = colorMap[variant];

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '6px 14px',
        borderRadius: '9999px',
        backgroundColor: c.bg,
        border: `1px solid ${c.border}`,
        color: c.text,
        fontSize: '14px',
        fontWeight: 700,
        fontFamily: THEME.fonts.mono,
        letterSpacing: '0.05em',
        boxShadow: `0 0 15px ${c.bg}`,
      }}
    >
      <span
        style={{
          width: '6px',
          height: '6px',
          borderRadius: '9999px',
          backgroundColor: c.border,
          marginRight: '8px',
          boxShadow: `0 0 8px ${c.border}`,
        }}
      />
      {label}
    </span>
  );
};
