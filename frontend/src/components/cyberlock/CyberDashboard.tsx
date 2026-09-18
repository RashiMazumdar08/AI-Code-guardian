"use client";

import React, { useState } from "react";
import {
  Lock,
  Globe,
  Activity,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Radio,
  ArrowUpRight,
  Plus,
  Terminal,
  Layers,
  Cpu,
  Zap,
} from "lucide-react";

interface CyberDashboardProps {
  onNavigatePlatform?: () => void;
}

export default function CyberDashboard({ onNavigatePlatform }: CyberDashboardProps) {
  const [activeTab, setActiveTab] = useState<"HOME" | "SERVICES" | "ABOUT" | "STORIES" | "CONTACT">("HOME");

  return (
    /* Full-Screen Webpage Layout in Deep Cyber Black/Blue (#0B0F19) */
    <div className="min-h-screen bg-[#0B0F19] text-[#f4f4f8] font-sans selection:bg-[#ff5400]/20 selection:text-[#ff5400]">
      
      {/* Container Wrapper */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-10 relative overflow-hidden">
        
        {/* Subtle Ambient Background Mesh & Dot Grid */}
        <div className="absolute inset-0 pointer-events-none opacity-25 bg-[radial-gradient(rgba(255,84,0,0.15)_1px,transparent_1px)] [background-size:32px_32px]" />

        {/* ------------------------------------------------------------- */}
        {/* TOP HEADER - Identical to image_12.png */}
        {/* ------------------------------------------------------------- */}
        <header className="relative z-10 flex flex-wrap items-center justify-between pb-8 border-b border-white/10 gap-4">

          
          {/* Brand Logo & Monospace Navigation Menu */}
          <div className="flex items-center gap-8">
            <div className="flex items-center gap-2.5 cursor-pointer group">
              <div className="w-7 h-7 rounded-md bg-[#181920] border border-white/15 flex items-center justify-center group-hover:border-[#ff5400] transition-colors">
                <Lock className="w-3.5 h-3.5 text-[#ff5400]" />
              </div>
              <span className="font-heading font-bold text-sm tracking-widest text-[#f4f4f8]">
                AI CODE <span className="text-[#ff5400]">GUARDIAN</span>
              </span>
            </div>

            {/* Monospace All-Caps Links */}
            <nav className="hidden md:flex items-center gap-6 font-mono text-[11px] tracking-[0.2em] text-[#8e8e9a]">
              {(["HOME", "SERVICES", "ABOUT", "STORIES", "CONTACT"] as const).map((link) => (
                <button
                  key={link}
                  onClick={() => setActiveTab(link)}
                  className={`hover:text-white transition-colors relative py-1 ${
                    activeTab === link ? "text-white font-bold" : ""
                  }`}
                >
                  {link}
                  {activeTab === link && (
                    <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#ff5400]" />
                  )}
                </button>
              ))}
            </nav>
          </div>

          {/* Right Pill Button */}
          <div className="flex items-center gap-3">
            {onNavigatePlatform && (
              <button
                onClick={onNavigatePlatform}
                className="hidden sm:flex items-center gap-2 font-mono text-[11px] tracking-wider px-4 py-2 rounded-full border border-white/15 text-[#8e8e9a] hover:border-[#ff5400] hover:text-[#ff5400] transition"
              >
                <Terminal className="w-3 h-3 text-[#ff5400]" />
                PLATFORM APP
              </button>
            )}
            <button className="font-mono text-[11px] tracking-widest px-5 py-2 rounded-full border border-white/20 text-[#f4f4f8] hover:border-[#ff5400] hover:text-[#ff5400] hover:bg-[#ff5400]/10 transition-all font-semibold shadow-sm">
              BOOK A CALL
            </button>
          </div>
        </header>

        {/* ------------------------------------------------------------- */}
        {/* UPPER TWO-PANEL SECTION (PROXIMITY & NEGATIVE SPACE BOUNDARIES) */}
        {/* ------------------------------------------------------------- */}
        <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-8 py-10">
          
          {/* UPPER LEFT: OVERVIEW PANEL WITH DIFFUSED PLANET BACKDROP */}
          <div className="lg:col-span-7 relative rounded-2xl p-6 sm:p-8 bg-[#12131a]/80 backdrop-blur-md overflow-hidden flex flex-col justify-between min-h-[420px] border border-white/5 shadow-inner">
            
            {/* Diffused Light-Planet / Orb Graphic Backdrop */}
            <div className="absolute -right-20 -bottom-20 w-[420px] h-[420px] rounded-full bg-[radial-gradient(circle_at_50%_50%,rgba(255,84,0,0.45)_0%,rgba(255,140,0,0.15)_40%,transparent_75%)] blur-2xl pointer-events-none" />
            <div className="absolute right-10 bottom-10 w-64 h-64 rounded-full border border-[#ff5400]/20 pointer-events-none animate-spin-slow opacity-40" />

            {/* Sub-Header Text from image_12.png */}
            <div className="space-y-4 relative z-10">
              <div className="font-mono text-[10px] sm:text-[11px] tracking-[0.2em] text-[#8e8e9a] uppercase font-semibold">
                WE ARE AN AI CODE SECURITY PLATFORM. MAKING CODE PROTECTION SIMPLE. SINCE 2021
              </div>

              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#181922] border border-white/10 text-xs font-mono text-[#ff5400]">
                <Lock className="w-3 h-3 text-[#ff5400]" />
                <span>SECURE BY DESIGN</span>
              </div>

              {/* Large Sans-Serif Heading */}
              <h1 className="font-heading text-3xl sm:text-5xl lg:text-6xl font-bold tracking-tight text-[#f4f4f8] leading-[1.08]">
                Protect what matters online
              </h1>

              <p className="text-sm text-[#8e8e9a] max-w-lg leading-relaxed font-normal">
                AI-powered code analysis that finds vulnerabilities, explains exploitability, and auto-fixes issues — with zero friction.
              </p>
            </div>

            {/* Action Buttons reproduced from image_12.png */}
            <div className="flex flex-wrap items-center gap-4 pt-8 relative z-10">
              <button className="font-mono font-bold text-xs tracking-wider px-6 py-3 rounded-full bg-[#ff5400] text-black hover:bg-[#ff6a1a] transition-all shadow-[0_0_20px_rgba(255,84,0,0.4)] flex items-center gap-2">
                <Lock className="w-3.5 h-3.5" />
                BOOK A CALL
              </button>

              <button className="font-mono text-xs tracking-wider px-6 py-3 rounded-full border border-white/20 text-[#f4f4f8] hover:border-[#ff5400] hover:text-[#ff5400] transition-all">
                VIEW SERVICES
              </button>
            </div>
          </div>

          {/* UPPER RIGHT: ACTIVE THREATS VECTOR MAP PANEL */}
          <div className="lg:col-span-5 rounded-2xl p-6 sm:p-8 bg-[#12131a]/80 backdrop-blur-md flex flex-col justify-between border border-white/5 relative overflow-hidden">
            
            <div>
              <div className="flex items-center justify-between mb-6">
                <div className="font-mono text-[11px] tracking-[0.2em] text-[#8e8e9a] uppercase flex items-center gap-2">
                  <Radio className="w-3.5 h-3.5 text-[#ff5400] animate-pulse" />
                  01 // ACTIVE THREATS
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#ff5400]/10 text-[#ff5400] border border-[#ff5400]/30 font-semibold">
                  LIVE TELEMETRY
                </span>
              </div>

              {/* Glowing Vector World Radar Visual */}
              <div className="relative h-56 w-full rounded-xl bg-[#090a0d] border border-white/10 p-4 flex flex-col justify-between overflow-hidden">
                <div className="absolute inset-0 opacity-15 bg-[radial-gradient(#ff5400_1px,transparent_1px)] [background-size:16px_16px]" />
                
                {/* Simulated Vector Paths */}
                <svg className="absolute inset-0 w-full h-full text-[#ff5400]/40 pointer-events-none" viewBox="0 0 400 200">
                  <path d="M 50 150 Q 150 50 250 120 T 350 40" fill="none" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4,4" />
                  <circle cx="50" cy="150" r="4" fill="#ff5400" className="animate-ping" />
                  <circle cx="250" cy="120" r="4" fill="#ff5400" />
                  <circle cx="350" cy="40" r="5" fill="#ff5400" />
                </svg>

                <div className="relative z-10 flex justify-between items-start text-[11px] font-mono text-[#8e8e9a]">
                  <div>
                    <span className="text-white font-bold block">GLOBAL VECTOR MONITORS</span>
                    <span>REGION: US-EAST / EU-CENTRAL</span>
                  </div>
                  <span className="text-[#ff5400] font-bold">2.4 Gbps VECTOR</span>
                </div>

                <div className="relative z-10 grid grid-cols-3 gap-2 text-center text-xs font-mono pt-4 border-t border-white/10">
                  <div className="bg-[#12131a] p-2 rounded">
                    <div className="text-[10px] text-[#8e8e9a]">BLOCKED</div>
                    <div className="text-[#ff5400] font-bold">14,290</div>
                  </div>
                  <div className="bg-[#12131a] p-2 rounded">
                    <div className="text-[10px] text-[#8e8e9a]">LATENCY</div>
                    <div className="text-white font-bold">0.4 ms</div>
                  </div>
                  <div className="bg-[#12131a] p-2 rounded">
                    <div className="text-[10px] text-[#8e8e9a]">STATUS</div>
                    <div className="text-emerald-400 font-bold">SHIELD ON</div>
                  </div>
                </div>
              </div>
            </div>

            <div className="pt-4 flex items-center justify-between text-xs font-mono text-[#8e8e9a]">
              <span>AUTOMATED RED TEAM SCAN</span>
              <span className="text-white font-bold">100% SINK GROUNDING</span>
            </div>

          </div>

        </div>

        {/* STRATEGIC CROSS-HAIR INTERSECTION MARKER FROM image_12.png */}
        <div className="relative py-2 flex items-center justify-between px-4 my-2 text-[#ff5400]/60">
          <Plus className="w-4 h-4" />
          <div className="h-[1px] flex-1 bg-white/10 mx-4" />
          <span className="text-[10px] font-mono tracking-widest text-[#8e8e9a]">SPATIAL SYSTEM BOUNDARY</span>
          <div className="h-[1px] flex-1 bg-white/10 mx-4" />
          <Plus className="w-4 h-4" />
        </div>

        {/* ------------------------------------------------------------- */}
        {/* LOWER TWO-PANEL SECTION (RISK PRIORITIZATION & INCIDENT LOG) */}
        {/* ------------------------------------------------------------- */}
        <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-8 pt-6">
          
          {/* LOWER LEFT: RISK PRIORITIZATION PANEL */}
          <div className="lg:col-span-6 rounded-2xl p-6 sm:p-8 bg-[#12131a]/80 backdrop-blur-md border border-white/5">
            <div className="flex items-center justify-between mb-6">
              <div className="font-mono text-[11px] tracking-[0.2em] text-[#8e8e9a] uppercase flex items-center gap-2">
                <ShieldAlert className="w-3.5 h-3.5 text-[#ff5400]" />
                02 // RISK PRIORITIZATION
              </div>
              <span className="text-[10px] font-mono text-[#ff5400]">3 TIERS IDENTIFIED</span>
            </div>

            {/* Tiered Vulnerabilities List */}
            <div className="space-y-3 font-mono text-xs">
              
              {/* Critical Tier */}
              <div className="p-3.5 rounded-xl bg-[#090a0d] border border-[#ff5400]/40 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="px-2 py-0.5 rounded bg-[#ff5400]/20 text-[#ff5400] font-bold border border-[#ff5400]/40 text-[10px]">
                    CRITICAL
                  </span>
                  <div>
                    <div className="text-white font-semibold">SQL Injection in payment_service.py</div>
                    <div className="text-[10px] text-[#8e8e9a]">CWE-89 • Taint flow to cursor.execute()</div>
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-[#ff5400] font-bold block">VULN-8902</span>
                  <span className="text-[10px] text-emerald-400">AUTOFICED</span>
                </div>
              </div>

              {/* High Tier */}
              <div className="p-3.5 rounded-xl bg-[#090a0d] border border-orange-500/30 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="px-2 py-0.5 rounded bg-orange-500/20 text-orange-400 font-bold border border-orange-500/30 text-[10px]">
                    HIGH
                  </span>
                  <div>
                    <div className="text-white font-semibold">Deprecated MD5 Hashing in crypto.py</div>
                    <div className="text-[10px] text-[#8e8e9a]">CWE-327 • Collision vulnerability</div>
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-orange-400 font-bold block">CRYPTO-327</span>
                  <span className="text-[10px] text-emerald-400">UPGRADED SHA-256</span>
                </div>
              </div>

              {/* Medium Tier */}
              <div className="p-3.5 rounded-xl bg-[#090a0d] border border-yellow-500/30 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="px-2 py-0.5 rounded bg-yellow-500/20 text-yellow-400 font-bold border border-yellow-500/30 text-[10px]">
                    MEDIUM
                  </span>
                  <div>
                    <div className="text-white font-semibold">Unverified SSL/TLS Certificate Context</div>
                    <div className="text-[10px] text-[#8e8e9a]">CWE-295 • verify=False flag</div>
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-yellow-400 font-bold block">TLS-295</span>
                  <span className="text-[10px] text-emerald-400">VALIDATED</span>
                </div>
              </div>

            </div>
          </div>

          {/* LOWER RIGHT: INCIDENT LOG TABLE PANEL */}
          <div className="lg:col-span-6 rounded-2xl p-6 sm:p-8 bg-[#12131a]/80 backdrop-blur-md border border-white/5">
            <div className="flex items-center justify-between mb-6">
              <div className="font-mono text-[11px] tracking-[0.2em] text-[#8e8e9a] uppercase flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-[#ff5400]" />
                03 // INCIDENT LOG
              </div>
              <span className="text-[10px] font-mono text-[#8e8e9a]">REAL-TIME EVENT STREAM</span>
            </div>

            {/* Technical Readout Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-white/10 text-[10px] text-[#8e8e9a]">
                    <th className="pb-2">TIME</th>
                    <th className="pb-2">EVENT SINK</th>
                    <th className="pb-2">SEVERITY</th>
                    <th className="pb-2 text-right">ACTION TAKEN</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 text-[#f4f4f8]">
                  <tr>
                    <td className="py-2.5 text-[#8e8e9a]">15:36:12</td>
                    <td className="py-2.5 font-bold">SQL_QUERY_SINK</td>
                    <td className="py-2.5 text-[#ff5400]">CRITICAL</td>
                    <td className="py-2.5 text-right text-emerald-400">PARAM_PATCHED</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 text-[#8e8e9a]">15:34:05</td>
                    <td className="py-2.5 font-bold">HASH_ALGO_CALL</td>
                    <td className="py-2.5 text-orange-400">HIGH</td>
                    <td className="py-2.5 text-right text-emerald-400">SHA256_UPGRADED</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 text-[#8e8e9a]">15:30:48</td>
                    <td className="py-2.5 font-bold">TLS_VERIFY_CALL</td>
                    <td className="py-2.5 text-yellow-400">MEDIUM</td>
                    <td className="py-2.5 text-right text-emerald-400">CONTEXT_ENFORCED</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 text-[#8e8e9a]">15:22:19</td>
                    <td className="py-2.5 font-bold">NIST_PQC_CHECK</td>
                    <td className="py-2.5 text-blue-400">INFO</td>
                    <td className="py-2.5 text-right text-[#ff5400]">CBOM_LOGGED</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

        </div>

        {/* Bottom Footer Credits */}
        <footer className="mt-12 pt-6 border-t border-white/10 flex flex-wrap items-center justify-between text-[11px] font-mono text-[#8e8e9a] gap-4">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#ff5400]" />
            <span>AI CODE GUARDIAN • UST + NEMOTRON ANALYSIS ENGINE</span>
          </div>
          <div>
            © 2026 AI CODE GUARDIAN. ALL RIGHTS RESERVED.
          </div>
        </footer>

      </div>
    </div>
  );
}
