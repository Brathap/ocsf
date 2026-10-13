import React from 'react';
import { THEME } from '../styles/theme';

export const GlassCard: React.FC<{
  children: React.ReactNode;
  style?: React.CSSProperties;
  glow?: boolean;
}> = ({ children, style, glow = false }) => {
  return (
    <div
      style={{
        backgroundColor: THEME.bgCard,
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        border: `1px solid ${glow ? THEME.borderGlow : THEME.borderColor}`,
        borderRadius: '24px',
        boxShadow: glow
          ? '0 20px 50px -10px rgba(6, 182, 212, 0.25), inset 0 1px 1px rgba(255, 255, 255, 0.2)'
          : '0 20px 40px -15px rgba(0, 0, 0, 0.5), inset 0 1px 1px rgba(255, 255, 255, 0.1)',
        padding: '24px',
        ...style,
      }}
    >
      {children}
    </div>
  );
};
