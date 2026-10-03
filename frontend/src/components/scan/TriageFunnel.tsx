"use client";

import React from "react";
import { AlertTriangle, ShieldAlert, Zap, Flame, ArrowRight } from "lucide-react";

export interface FunnelMetrics {
  total_alerts: number;
  exploitable_count: number;
  high_priority_count: number;
  immediate_risk_count: number;
}

interface TriageFunnelProps {
  metrics: FunnelMetrics;
  onFilterClick?: (filterType: string) => void;
}

export const TriageFunnel: React.FC<TriageFunnelProps> = ({ metrics, onFilterClick }) => {
  const funnelSteps = [
    {
      id: "total",
      label: "TOTAL SCAN ALERTS",
      count: metrics.total_alerts,
      icon: AlertTriangle,
      accent: "border-[#DCE5F0]",
      iconColor: "text-slate-500",
      description: "Raw detections across static & UST engines",
    },
    {
      id: "exploitable",
      label: "REACHABLE & EXPLOITABLE",
      count: metrics.exploitable_count,
      icon: ShieldAlert,
      accent: "border-blue-200",
      iconColor: "text-blue-600",
      description: "Confirmed taint flows reaching sinks",
    },
    {
      id: "high_priority",
      label: "HIGH PRIORITY",
      count: metrics.high_priority_count,
      icon: Zap,
      accent: "border-amber-200",
      iconColor: "text-amber-600",
      description: "Critical & High severity findings",
    },
    {
      id: "immediate_risk",
      label: "IMMEDIATE RISK",
      count: metrics.immediate_risk_count,
      icon: Flame,
      accent: "border-rose-200",
      iconColor: "text-rose-600",
      description: "Reachable Critical/High vulnerabilities",
    },
  ];

  return (
    <div className="w-full my-4">
      <div className="text-[10px] font-mono font-semibold uppercase tracking-[0.2em] text-slate-500 mb-3 flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-blue-600 animate-pulse" />
        TRIAGE FUNNEL &amp; RISK PRIORITIZATION
      </div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        {funnelSteps.map((step, index) => {
          const Icon = step.icon;
          return (
            <div
              key={step.id}
              onClick={() => onFilterClick && onFilterClick(step.id)}
              className={`relative flex flex-col justify-between p-4 rounded-xl bg-white border ${step.accent} cursor-pointer transition-all duration-200 hover:border-blue-500 hover:bg-slate-50 shadow-sm group`}
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-[10px] font-mono font-semibold tracking-wider text-slate-500 group-hover:text-[#111827] transition-colors">
                  {step.label}
                </span>
                <Icon className={`w-4 h-4 ${step.iconColor}`} />
              </div>
              <div className="my-1">
                <span className="text-3xl font-bold tracking-tight font-mono text-[#111827]">{step.count}</span>
              </div>
              <p className="text-[10px] font-mono text-slate-500 truncate mt-1">{step.description}</p>

              {index < funnelSteps.length - 1 && (
                <div className="hidden md:block absolute -right-3.5 top-1/2 -translate-y-1/2 z-10 text-slate-400">
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default TriageFunnel;
