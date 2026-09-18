"use client";

import React from "react";
import {
  Shield,
  FolderGit2,
  GitBranch,
  ChevronDown,
  Activity,
  User,
  Bell,
  Settings,
} from "lucide-react";

interface AuraHeaderProps {
  securityScore?: number;
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  repoName?: string;
  branchName?: string;
}

export default function AuraHeader({
  securityScore = 78,
  criticalCount = 5,
  highCount = 24,
  mediumCount = 10,
  repoName = "acg_repo_v2",
  branchName = "feature/auth-hardening",
}: AuraHeaderProps) {
  return (
    <header className="h-[52px] bg-[#111726] border-b border-slate-800 px-5 flex items-center justify-between shrink-0 font-sans text-slate-200 z-30 shadow-md">
      
      {/* LEFT & CENTER-LEFT: Brand Logo, Repo & Branch Switcher */}
      <div className="flex items-center gap-4">
        {/* Brand Shield Logo */}
        <div className="flex items-center gap-2.5 cursor-pointer group">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center text-white shadow-lg transition-transform group-hover:scale-105"
            style={{
              background: "linear-gradient(135deg, #FF5E1E 0%, #FF8C42 100%)",
              boxShadow: "0 0 16px rgba(255, 94, 30, 0.4)",
            }}
          >
            <Shield className="w-4 h-4 fill-white/20" />
          </div>
          <div className="flex flex-col">
            <span className="font-mono font-bold text-xs tracking-wider text-white leading-none">
              AURA <span className="text-[#FF5E1E]">SECURITY</span>
            </span>
            <span className="text-[9px] font-mono text-slate-400 leading-tight">
              AI Code Guardian
            </span>
          </div>
        </div>

        <div className="h-5 w-[1px] bg-slate-800 hidden sm:block" />

        {/* Project Dropdown Selector */}
        <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#090D16] border border-slate-800 cursor-pointer hover:border-slate-700 transition-colors">
          <FolderGit2 className="w-3.5 h-3.5 text-[#FF5E1E]" />
          <div className="flex items-center gap-1.5 font-mono text-xs text-slate-200">
            <span className="font-bold">{repoName}</span>
            <span className="text-slate-500">/</span>
            <span className="text-slate-400">main</span>
          </div>
          <ChevronDown className="w-3 h-3 text-slate-500 ml-1" />
        </div>

        {/* Branch Switcher */}
        <div className="hidden md:flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-blue-500/10 border border-blue-500/20 cursor-pointer hover:bg-blue-500/15 transition-colors">
          <GitBranch className="w-3.5 h-3.5 text-blue-400" />
          <span className="font-mono text-xs font-semibold text-blue-300">
            {branchName}
          </span>
          <ChevronDown className="w-3 h-3 text-blue-400 ml-1" />
        </div>
      </div>

      {/* CENTER-RIGHT & RIGHT: Security Score Gauge, Status Pill, Severity Counters, Profile */}
      <div className="flex items-center gap-4">
        
        {/* Circular AI Security Score Gauge */}
        <div className="flex items-center gap-2.5 px-3 py-1 rounded-xl bg-[#090D16] border border-slate-800">
          <div className="relative w-9 h-9 flex items-center justify-center">
            <svg className="w-9 h-9 -rotate-90" viewBox="0 0 36 36">
              <path
                className="text-slate-800 stroke-current"
                strokeWidth="3.5"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
              <path
                className="stroke-current transition-all duration-1000 ease-out"
                style={{ color: "#FF5E1E" }}
                strokeWidth="3.5"
                strokeDasharray={`${securityScore}, 100`}
                strokeLinecap="round"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
            </svg>
            <span className="absolute font-mono font-extrabold text-[11px] text-white">
              {securityScore}
            </span>
          </div>
          <div className="flex flex-col text-left leading-tight">
            <span className="text-xs font-bold text-[#FF5E1E] flex items-center gap-1">
              Improving <span className="text-[10px]">↗</span>
            </span>
            <span className="text-[9px] font-mono text-slate-400">Security Score</span>
          </div>
        </div>

        {/* Status Pill ("Analysis Active") */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/25">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_#22C55E]" />
          <span className="text-[10px] font-mono font-bold text-emerald-300 tracking-wide uppercase">
            Analysis Active
          </span>
        </div>

        <div className="h-5 w-[1px] bg-slate-800 hidden sm:block" />

        {/* Severity Counter Pills */}
        <div className="flex items-center gap-1.5">
          {/* Critical (Red #EF4444) */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-red-500/15 border border-red-500/30 font-mono text-[11px] font-bold text-red-300">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500 shadow-[0_0_6px_#EF4444]" />
            <span>Critical</span>
            <span className="px-1.5 py-0.2 rounded-full bg-red-500/30 text-white text-[10px]">
              {criticalCount}
            </span>
          </div>

          {/* High (Orange #FF5E1E) */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-orange-500/15 border border-orange-500/30 font-mono text-[11px] font-bold text-orange-300">
            <span className="w-1.5 h-1.5 rounded-full bg-[#FF5E1E] shadow-[0_0_6px_#FF5E1E]" />
            <span>High</span>
            <span className="px-1.5 py-0.2 rounded-full bg-orange-500/30 text-white text-[10px]">
              {highCount}
            </span>
          </div>

          {/* Medium (Yellow #F59E0B) */}
          <div className="hidden xl:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500/15 border border-amber-500/30 font-mono text-[11px] font-bold text-amber-300">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shadow-[0_0_6px_#F59E0B]" />
            <span>Med</span>
            <span className="px-1.5 py-0.2 rounded-full bg-amber-500/30 text-white text-[10px]">
              {mediumCount}
            </span>
          </div>
        </div>

        {/* Profile Avatar */}
        <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-indigo-600 to-purple-600 border-2 border-indigo-400/40 flex items-center justify-center font-mono font-bold text-xs text-white cursor-pointer hover:border-indigo-300 transition-colors shadow-md">
          KO
        </div>
      </div>
    </header>
  );
}
