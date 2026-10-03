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
    /* Full-Screen Webpage Layout in Enterprise Light Theme (#F5F7FA) */
    <div className="min-h-screen bg-[#F5F7FA] text-[#111827] font-sans selection:bg-[#EFF6FF] selection:text-[#2563EB]">
      
      {/* Container Wrapper */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-10 relative overflow-hidden">
        
        {/* Subtle Ambient Background Dot Grid */}
        <div className="absolute inset-0 pointer-events-none opacity-40 bg-[radial-gradient(#CBD5E1_1px,transparent_1px)] [background-size:32px_32px]" />

        {/* ------------------------------------------------------------- */}
        {/* TOP HEADER */}
        {/* ------------------------------------------------------------- */}
        <header className="relative z-10 flex flex-wrap items-center justify-between pb-8 border-b border-[#E2E8F0] gap-4">

          {/* Brand Logo & Monospace Navigation Menu */}
          <div className="flex items-center gap-8">
            <div className="flex items-center gap-2.5 cursor-pointer group">
              <div className="w-7 h-7 rounded-md bg-[#EFF6FF] border border-[#BFDBFE] flex items-center justify-center group-hover:border-[#2563EB] transition-colors">
                <Lock className="w-3.5 h-3.5 text-[#2563EB]" />
              </div>
              <span className="font-heading font-bold text-sm tracking-widest text-[#111827]">
                AI CODE <span className="text-[#2563EB]">GUARDIAN</span>
              </span>
            </div>

            {/* Monospace All-Caps Links */}
            <nav className="hidden md:flex items-center gap-6 font-mono text-[11px] tracking-[0.2em] text-[#64748B]">
              {(["HOME", "SERVICES", "ABOUT", "STORIES", "CONTACT"] as const).map((link) => (
                <button
                  key={link}
                  onClick={() => setActiveTab(link)}
                  className={`hover:text-[#111827] transition-colors relative py-1 ${
                    activeTab === link ? "text-[#111827] font-bold" : ""
                  }`}
                >
                  {link}
                  {activeTab === link && (
                    <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#2563EB]" />
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
                className="hidden sm:flex items-center gap-2 font-mono text-[11px] tracking-wider px-4 py-2 rounded-full border border-[#E2E8F0] bg-white text-[#475569] hover:border-[#BFDBFE] hover:text-[#2563EB] hover:bg-[#EFF6FF] transition shadow-sm"
              >
                <Terminal className="w-3 h-3 text-[#2563EB]" />
                PLATFORM APP
              </button>
            )}
            <button className="font-mono text-[11px] tracking-widest px-5 py-2 rounded-full bg-[#2563EB] text-white hover:bg-[#1D4ED8] transition-all font-semibold shadow-sm">
              BOOK A CALL
            </button>
          </div>
        </header>

        {/* ------------------------------------------------------------- */}
        {/* UPPER TWO-PANEL SECTION */}
        {/* ------------------------------------------------------------- */}
        <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-8 py-10">
          
          {/* UPPER LEFT: OVERVIEW PANEL WITH LIGHT BLUE BACKDROP */}
          <div className="lg:col-span-7 relative rounded-2xl p-6 sm:p-8 bg-white overflow-hidden flex flex-col justify-between min-h-[420px] border border-[#E2E8F0] shadow-sm">
            
            {/* Diffused Light Blue Orb Graphic Backdrop */}
            <div className="absolute -right-20 -bottom-20 w-[420px] h-[420px] rounded-full bg-[radial-gradient(circle_at_50%_50%,rgba(37,99,235,0.15)_0%,rgba(191,219,254,0.08)_40%,transparent_75%)] blur-2xl pointer-events-none" />
            <div className="absolute right-10 bottom-10 w-64 h-64 rounded-full border border-blue-200 pointer-events-none animate-spin-slow opacity-40" />

            {/* Sub-Header Text */}
            <div className="space-y-4 relative z-10">
              <div className="font-mono text-[10px] sm:text-[11px] tracking-[0.2em] text-[#64748B] uppercase font-semibold">
                WE ARE AN AI CODE SECURITY PLATFORM. MAKING CODE PROTECTION SIMPLE. SINCE 2021
              </div>

              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#EFF6FF] border border-[#BFDBFE] text-xs font-mono text-[#2563EB]">
                <Lock className="w-3 h-3 text-[#2563EB]" />
                <span>SECURE BY DESIGN</span>
              </div>

              {/* Large Sans-Serif Heading */}
              <h1 className="font-heading text-3xl sm:text-5xl lg:text-6xl font-bold tracking-tight text-[#111827] leading-[1.08]">
                Protect what matters online
              </h1>

              <p className="text-sm text-[#64748B] max-w-lg leading-relaxed font-normal">
                AI-powered code analysis that finds vulnerabilities, explains exploitability, and auto-fixes issues — with zero friction.
              </p>
            </div>

            {/* Action Buttons */}
            <div className="flex flex-wrap items-center gap-4 pt-8 relative z-10">
              <button className="font-mono font-bold text-xs tracking-wider px-6 py-3 rounded-full bg-[#2563EB] text-white hover:bg-[#1D4ED8] transition-all shadow-sm flex items-center gap-2">
                <Lock className="w-3.5 h-3.5" />
                BOOK A CALL
              </button>

              <button className="font-mono text-xs tracking-wider px-6 py-3 rounded-full border border-[#E2E8F0] bg-white text-[#111827] hover:border-[#BFDBFE] hover:bg-[#EFF6FF] hover:text-[#2563EB] transition-all shadow-sm">
                VIEW SERVICES
              </button>
            </div>
          </div>

          {/* UPPER RIGHT: ACTIVE THREATS VECTOR MAP PANEL */}
          <div className="lg:col-span-5 rounded-2xl p-6 sm:p-8 bg-white flex flex-col justify-between border border-[#E2E8F0] relative overflow-hidden shadow-sm">
            
            <div>
              <div className="flex items-center justify-between mb-6">
                <div className="font-mono text-[11px] tracking-[0.2em] text-[#64748B] uppercase flex items-center gap-2">
                  <Radio className="w-3.5 h-3.5 text-[#2563EB] animate-pulse" />
                  01 // ACTIVE THREATS
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#EFF6FF] text-[#2563EB] border border-[#BFDBFE] font-semibold">
                  LIVE TELEMETRY
                </span>
              </div>

              {/* Glowing Vector World Radar Visual */}
              <div className="relative h-56 w-full rounded-xl bg-[#F8FAFC] border border-[#E2E8F0] p-4 flex flex-col justify-between overflow-hidden">
                <div className="absolute inset-0 opacity-15 bg-[radial-gradient(#2563EB_1px,transparent_1px)] [background-size:16px_16px]" />
                
                {/* Simulated Vector Paths */}
                <svg className="absolute inset-0 w-full h-full text-blue-400 pointer-events-none" viewBox="0 0 400 200">
                  <path d="M 50 150 Q 150 50 250 120 T 350 40" fill="none" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4,4" />
                  <circle cx="50" cy="150" r="4" fill="#2563EB" className="animate-ping" />
                  <circle cx="250" cy="120" r="4" fill="#2563EB" />
                  <circle cx="350" cy="40" r="5" fill="#2563EB" />
                </svg>

                <div className="relative z-10 flex justify-between items-start text-[11px] font-mono text-[#64748B]">
                  <div>
                    <span className="text-[#111827] font-bold block">GLOBAL VECTOR MONITORS</span>
                    <span>REGION: US-EAST / EU-CENTRAL</span>
                  </div>
                  <span className="text-[#2563EB] font-bold">2.4 Gbps VECTOR</span>
                </div>

                <div className="relative z-10 grid grid-cols-3 gap-2 text-center text-xs font-mono pt-4 border-t border-[#E2E8F0]">
                  <div className="bg-white p-2 rounded border border-[#E2E8F0]">
                    <div className="text-[10px] text-[#64748B]">BLOCKED</div>
                    <div className="text-[#2563EB] font-bold">14,290</div>
                  </div>
                  <div className="bg-white p-2 rounded border border-[#E2E8F0]">
                    <div className="text-[10px] text-[#64748B]">LATENCY</div>
                    <div className="text-[#111827] font-bold">0.4 ms</div>
                  </div>
                  <div className="bg-white p-2 rounded border border-[#E2E8F0]">
                    <div className="text-[10px] text-[#64748B]">STATUS</div>
                    <div className="text-emerald-600 font-bold">SHIELD ON</div>
                  </div>
                </div>
              </div>
            </div>

            <div className="pt-4 flex items-center justify-between text-xs font-mono text-[#64748B]">
              <span>AUTOMATED RED TEAM SCAN</span>
              <span className="text-[#111827] font-bold">100% SINK GROUNDING</span>
            </div>

          </div>

        </div>

        {/* STRATEGIC CROSS-HAIR INTERSECTION MARKER */}
        <div className="relative py-2 flex items-center justify-between px-4 my-2 text-[#2563EB]">
          <Plus className="w-4 h-4" />
          <div className="h-[1px] flex-1 bg-[#E2E8F0] mx-4" />
          <span className="text-[10px] font-mono tracking-widest text-[#64748B]">SPATIAL SYSTEM BOUNDARY</span>
          <div className="h-[1px] flex-1 bg-[#E2E8F0] mx-4" />
          <Plus className="w-4 h-4" />
        </div>

        {/* ------------------------------------------------------------- */}
        {/* LOWER TWO-PANEL SECTION */}
        {/* ------------------------------------------------------------- */}
        <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-8 pt-6">
          
          {/* LOWER LEFT: RISK PRIORITIZATION PANEL */}
          <div className="lg:col-span-6 rounded-2xl p-6 sm:p-8 bg-white border border-[#E2E8F0] shadow-sm">
            <div className="flex items-center justify-between mb-6">
              <div className="font-mono text-[11px] tracking-[0.2em] text-[#64748B] uppercase flex items-center gap-2">
                <ShieldAlert className="w-3.5 h-3.5 text-red-600" />
                02 // RISK PRIORITIZATION
              </div>
              <span className="text-[10px] font-mono text-[#2563EB] font-semibold">3 TIERS IDENTIFIED</span>
            </div>

            {/* Tiered Vulnerabilities List */}
            <div className="space-y-3 font-mono text-xs">
              
              {/* Critical Tier */}
              <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="px-2 py-0.5 rounded bg-red-100 text-red-700 font-bold border border-red-200 text-[10px]">
                    CRITICAL
                  </span>
                  <div>
                    <div className="text-[#111827] font-semibold">SQL Injection in payment_service.py</div>
                    <div className="text-[10px] text-[#64748B]">CWE-89 • Taint flow to cursor.execute()</div>
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-red-700 font-bold block">VULN-8902</span>
                  <span className="text-[10px] text-emerald-600 font-bold">AUTOFIXED</span>
                </div>
              </div>

              {/* High Tier */}
              <div className="p-3.5 rounded-xl bg-orange-50 border border-orange-200 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="px-2 py-0.5 rounded bg-orange-100 text-orange-700 font-bold border border-orange-200 text-[10px]">
                    HIGH
                  </span>
                  <div>
                    <div className="text-[#111827] font-semibold">Deprecated MD5 Hashing in crypto.py</div>
                    <div className="text-[10px] text-[#64748B]">CWE-327 • Collision vulnerability</div>
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-orange-700 font-bold block">CRYPTO-327</span>
                  <span className="text-[10px] text-emerald-600 font-bold">UPGRADED SHA-256</span>
                </div>
              </div>

              {/* Medium Tier */}
              <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="px-2 py-0.5 rounded bg-amber-100 text-amber-700 font-bold border border-amber-200 text-[10px]">
                    MEDIUM
                  </span>
                  <div>
                    <div className="text-[#111827] font-semibold">Unverified SSL/TLS Certificate Context</div>
                    <div className="text-[10px] text-[#64748B]">CWE-295 • verify=False flag</div>
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-amber-700 font-bold block">TLS-295</span>
                  <span className="text-[10px] text-emerald-600 font-bold">VALIDATED</span>
                </div>
              </div>

            </div>
          </div>

          {/* LOWER RIGHT: INCIDENT LOG TABLE PANEL */}
          <div className="lg:col-span-6 rounded-2xl p-6 sm:p-8 bg-white border border-[#E2E8F0] shadow-sm">
            <div className="flex items-center justify-between mb-6">
              <div className="font-mono text-[11px] tracking-[0.2em] text-[#64748B] uppercase flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-[#2563EB]" />
                03 // INCIDENT LOG
              </div>
              <span className="text-[10px] font-mono text-[#64748B]">REAL-TIME EVENT STREAM</span>
            </div>

            {/* Technical Readout Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-[#E2E8F0] text-[10px] text-[#64748B]">
                    <th className="pb-2">TIME</th>
                    <th className="pb-2">EVENT SINK</th>
                    <th className="pb-2">SEVERITY</th>
                    <th className="pb-2 text-right">ACTION TAKEN</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E2E8F0] text-[#111827]">
                  <tr>
                    <td className="py-2.5 text-[#64748B]">15:36:12</td>
                    <td className="py-2.5 font-bold">SQL_QUERY_SINK</td>
                    <td className="py-2.5 text-red-600 font-bold">CRITICAL</td>
                    <td className="py-2.5 text-right text-emerald-600 font-bold">PARAM_PATCHED</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 text-[#64748B]">15:34:05</td>
                    <td className="py-2.5 font-bold">HASH_ALGO_CALL</td>
                    <td className="py-2.5 text-orange-600 font-bold">HIGH</td>
                    <td className="py-2.5 text-right text-emerald-600 font-bold">SHA256_UPGRADED</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 text-[#64748B]">15:30:48</td>
                    <td className="py-2.5 font-bold">TLS_VERIFY_CALL</td>
                    <td className="py-2.5 text-amber-600 font-bold">MEDIUM</td>
                    <td className="py-2.5 text-right text-emerald-600 font-bold">CONTEXT_ENFORCED</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 text-[#64748B]">15:22:19</td>
                    <td className="py-2.5 font-bold">NIST_PQC_CHECK</td>
                    <td className="py-2.5 text-blue-600 font-bold">INFO</td>
                    <td className="py-2.5 text-right text-[#2563EB]">CBOM_LOGGED</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

        </div>

        {/* Bottom Footer Credits */}
        <footer className="mt-12 pt-6 border-t border-[#E2E8F0] flex flex-wrap items-center justify-between text-[11px] font-mono text-[#64748B] gap-4">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#2563EB]" />
            <span>AI CODE GUARDIAN • UST ANALYSIS ENGINE</span>
          </div>
          <div>
            © 2026 AI CODE GUARDIAN. ALL RIGHTS RESERVED.
          </div>
        </footer>

      </div>
    </div>
  );
}
