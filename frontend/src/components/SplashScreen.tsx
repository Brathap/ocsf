import React, { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { ArrowRight, ShieldCheck, Database, Lock, Cpu, Server, CheckCircle2, Zap } from 'lucide-react';

interface SplashScreenProps {
  onComplete: () => void;
  brandName?: string;
  subTitle?: string;
}

interface LogPacket {
  id: number;
  protocol: 'SYSLOG' | 'CEF' | 'JOURNALD' | 'NETFLOW';
  src: string;
  dst: string;
  msg: string;
  y: number;
  speed: number;
  stage: 'RAW' | 'PII_SCRUB' | 'MERKLE_SEAL' | 'OCSF';
}

export const SplashScreen: React.FC<SplashScreenProps> = ({
  onComplete,
  brandName = "ULPF SENTINEL",
  subTitle = "Universal Log Pre-processing & Normalization Framework"
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [progress, setProgress] = useState(0);
  const [activeStage, setActiveStage] = useState(0);

  const stages = [
    { title: "Raw Wire Listener", sub: "UDP 5140 / Lossless TCP 6514 stream sockets bound", icon: Server },
    { title: "Verhoeff PII Scrubber", sub: "Deterministic in-memory redaction (Aadhaar, PAN, Emails)", icon: Lock },
    { title: "RFC 6962 Merkle Seal", sub: "SHA-256 non-repudiation cryptographic verification ledger", icon: Database },
    { title: "OCSF v1.1.0 Taxonomy", sub: "Standard schema output ready for zero-copy SOC ingestion", icon: ShieldCheck }
  ];

  // Pipeline stream canvas animation: raw log streams converging into normalized OCSF ledger
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    const packets: LogPacket[] = [];
    const protocols: ('SYSLOG' | 'CEF' | 'JOURNALD' | 'NETFLOW')[] = ['SYSLOG', 'CEF', 'JOURNALD', 'NETFLOW'];
    const sampleIps = ['198.51.100.23', '203.0.113.84', '10.240.1.15', '172.16.125.32'];

    for (let i = 0; i < 18; i++) {
      packets.push({
        id: i,
        protocol: protocols[i % protocols.length],
        src: sampleIps[i % sampleIps.length],
        dst: '10.0.0.1',
        msg: i % 2 === 0 ? 'Firewall Drop ACL: OUTSIDE_IN' : 'WAF Rule Triggered: SQLi Block',
        y: Math.random() * height,
        speed: 1.5 + Math.random() * 2.2,
        stage: i < 5 ? 'RAW' : i < 10 ? 'PII_SCRUB' : i < 15 ? 'MERKLE_SEAL' : 'OCSF'
      });
    }

    let t = 0;
    const render = () => {
      t += 0.02;
      ctx.clearRect(0, 0, width, height);

      // Deep SOC Background
      const bg = ctx.createLinearGradient(0, 0, width, height);
      bg.addColorStop(0, '#04070d');
      bg.addColorStop(0.5, '#070c18');
      bg.addColorStop(1, '#020509');
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, width, height);

      // Subtle Datacenter Grid
      ctx.strokeStyle = 'rgba(30, 41, 59, 0.45)';
      ctx.lineWidth = 1;
      const gridSize = 48;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // Draw horizontal high-speed data flow pipelines
      const laneY = [height * 0.28, height * 0.42, height * 0.58, height * 0.72];
      laneY.forEach((ly, idx) => {
        ctx.strokeStyle = idx % 2 === 0 ? 'rgba(59, 130, 246, 0.15)' : 'rgba(16, 185, 129, 0.12)';
        ctx.lineWidth = 2;
        ctx.setLineDash([8, 12]);
        ctx.lineDashOffset = -t * 20;
        ctx.beginPath();
        ctx.moveTo(0, ly);
        ctx.lineTo(width, ly);
        ctx.stroke();
        ctx.setLineDash([]);
      });

      // Flow log packets across pipelines
      packets.forEach((p, idx) => {
        p.y = laneY[idx % laneY.length];
        const px = ((t * p.speed * 85 + p.id * 140) % (width + 240)) - 120;

        // Packet node glow
        const glowColor = p.protocol === 'CEF' ? '#f43f5e' : p.protocol === 'JOURNALD' ? '#6366f1' : '#0ea5e9';
        ctx.fillStyle = glowColor;
        ctx.shadowColor = glowColor;
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(px, p.y, 4, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        // Stream label
        ctx.font = '10px "JetBrains Mono", monospace';
        ctx.fillStyle = 'rgba(148, 163, 184, 0.65)';
        ctx.fillText(`[${p.protocol}] ${p.src} → ${p.dst}`, px + 8, p.y - 6);
      });

      animId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  // Timed progress sequence directly mapping to ULPF architecture
  useEffect(() => {
    const interval = setInterval(() => {
      setProgress((prev) => {
        const next = prev + 1;
        if (next < 25) setActiveStage(0);
        else if (next < 50) setActiveStage(1);
        else if (next < 75) setActiveStage(2);
        else setActiveStage(3);

        if (next >= 100) {
          clearInterval(interval);
          setTimeout(onComplete, 350);
          return 100;
        }
        return next;
      });
    }, 28);

    return () => clearInterval(interval);
  }, [onComplete]);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.35, ease: "easeInOut" }}
      className="fixed inset-0 z-50 flex flex-col justify-between text-slate-100 select-none overflow-hidden font-sans"
    >
      {/* Background Interactive Architecture Canvas */}
      <canvas ref={canvasRef} className="absolute inset-0 block w-full h-full" />

      {/* Top Header Bar */}
      <div className="relative z-10 w-full max-w-7xl mx-auto px-6 py-5 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/40 backdrop-blur-md">
            <Zap className="w-4 h-4 text-blue-400" />
          </div>
          <div>
            <div className="text-xs font-mono font-bold tracking-widest text-slate-200 uppercase">
              PIPELINE BOOTSTRAP INITIALIZATION
            </div>
            <div className="text-[11px] text-blue-400 font-mono flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              AIR-GAP ENFORCED · ZERO EGRESS
            </div>
          </div>
        </div>

        <button
          onClick={onComplete}
          className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600/30 hover:bg-blue-600/50 border border-blue-400/40 text-xs font-mono font-bold text-blue-200 hover:text-white transition-all backdrop-blur-md cursor-pointer shadow-sm"
        >
          <span>ENTER CONSOLE</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Central Pipeline Stages Card */}
      <div className="relative z-10 max-w-4xl mx-auto w-full px-6 py-8">
        <div className="bg-slate-900/85 border border-slate-800 backdrop-blur-xl rounded-2xl p-6 sm:p-8 shadow-2xl space-y-6">
          <div className="text-center space-y-1.5">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-950/70 border border-blue-500/30 text-blue-300 text-xs font-mono font-bold">
              <Cpu className="w-3.5 h-3.5 text-blue-400" />
              <span>PRE-PROCESSING & NORMALIZATION ENGINE</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-black font-mono tracking-tight text-white uppercase">
              {brandName}
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 max-w-lg mx-auto">
              {subTitle}
            </p>
          </div>

          {/* 4 Pipeline Stages directly showing how raw logs turn into OCSF */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-2">
            {stages.map((st, idx) => {
              const Icon = st.icon;
              const isPast = activeStage > idx || progress === 100;
              const isCurrent = activeStage === idx && progress < 100;

              return (
                <div
                  key={st.title}
                  className={`p-3.5 rounded-xl border transition-all duration-200 ${
                    isPast
                      ? 'bg-emerald-950/30 border-emerald-700/50 text-emerald-200'
                      : isCurrent
                      ? 'bg-blue-950/40 border-blue-500/70 text-blue-100 shadow-md ring-1 ring-blue-500/30'
                      : 'bg-slate-950/50 border-slate-800/80 text-slate-500'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">
                      Phase 0{idx + 1}
                    </span>
                    {isPast ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <Icon className={`w-4 h-4 ${isCurrent ? 'text-blue-400 animate-pulse' : 'text-slate-600'}`} />
                    )}
                  </div>
                  <div className="text-xs font-mono font-bold text-slate-100 mb-1">
                    {st.title}
                  </div>
                  <div className="text-[11px] text-slate-400 font-sans leading-tight">
                    {st.sub}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Progress Bar & Numeric Status */}
          <div className="space-y-2 pt-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-blue-400 font-bold flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-blue-500 animate-ping" />
                <span>
                  {activeStage === 0 && "LISTENING ON UDP 5140 & TCP 6514..."}
                  {activeStage === 1 && "ENGAGING VERHOEFF DIHEDRAL D5 PII REDACTOR..."}
                  {activeStage === 2 && "COMPUTING RFC 6962 SHA-256 PROVENANCE TREE..."}
                  {activeStage === 3 && "NORMALIZING TO OCSF v1.1.0 TAXONOMY..."}
                </span>
              </span>
              <span className="text-sm font-mono font-black text-white">{progress}%</span>
            </div>
            <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800 p-0.5">
              <motion.div
                className="h-full bg-gradient-to-r from-blue-500 via-cyan-400 to-emerald-400 rounded-full"
                style={{ width: `${progress}%` }}
                transition={{ ease: "easeOut", duration: 0.05 }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Footer Info Strip */}
      <div className="relative z-10 w-full max-w-7xl mx-auto px-6 py-4 flex flex-wrap items-center justify-between text-xs font-mono text-slate-500 gap-2 border-t border-slate-800/80 bg-slate-950/80 backdrop-blur-md">
        <div className="flex items-center space-x-3">
          <span>Engine: <strong className="text-slate-300">Vector VRL + FastAPI Gateway</strong></span>
          <span>•</span>
          <span>Storage: <strong className="text-slate-300">SQLite WAL + Lossless JSONL</strong></span>
        </div>
        <div className="text-slate-400">
          Air-Gapped Sovereign Ingestion Core
        </div>
      </div>
    </motion.div>
  );
};
