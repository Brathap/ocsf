import React, { useEffect, useRef } from 'react';

interface AnimatedCounterProps {
  value: number;
  duration?: number;
  formatter?: (val: number) => string;
  className?: string;
}

export const AnimatedCounter: React.FC<AnimatedCounterProps> = ({
  value,
  duration = 600,
  formatter = (v) => Math.round(v).toLocaleString(),
  className = ''
}) => {
  const [displayValue, setDisplayValue] = React.useState(value);
  const prevValRef = useRef(value);
  const startTimeRef = useRef<number | null>(null);

  useEffect(() => {
    const startVal = prevValRef.current;
    startTimeRef.current = null;

    let animId: number;

    const step = (timestamp: number) => {
      if (!startTimeRef.current) startTimeRef.current = timestamp;
      const progress = Math.min((timestamp - startTimeRef.current) / duration, 1);
      // easeOutExpo
      const ease = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
      const current = startVal + (value - startVal) * ease;
      setDisplayValue(current);

      if (progress < 1) {
        animId = requestAnimationFrame(step);
      } else {
        setDisplayValue(value);
        prevValRef.current = value;
      }
    };

    animId = requestAnimationFrame(step);
    return () => {
      cancelAnimationFrame(animId);
      prevValRef.current = value;
    };
  }, [value, duration]);

  return <span className={className}>{formatter(displayValue)}</span>;
};
