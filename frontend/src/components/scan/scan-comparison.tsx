"use client";

import React from "react";
import type { ScanResult } from "@dns-checker/shared";
import { ArrowRight, ShieldCheck, TrendingUp, AlertTriangle, Verified, Scale, History, ShieldPlus } from "lucide-react";
import { ScanResults } from "./scan-results";
import { cn } from "@/lib/cn";

interface ScanComparisonProps {
  current: ScanResult;
  previous: ScanResult | null;
}

export function ScanComparison({ current, previous }: ScanComparisonProps) {
  if (!previous) {
    return (
      <div className="card border-surface-200/60 bg-white p-12 text-center mt-8">
        <ShieldCheck className="h-12 w-12 text-brand-500 mx-auto mb-4" />
        <h3 className="text-xl font-black text-surface-900 uppercase tracking-tighter mb-2">Baseline Established</h3>
        <p className="text-surface-500 text-sm max-w-md mx-auto leading-relaxed">
          This is your first security audit. Once you implement the recommended security headers and SSL hardening, your next scan will generate a full "Before & After" intelligence report here.
        </p>
      </div>
    );
  }

  const currentScore = current.security?.score || 0;
  const previousScore = previous.security?.score || 0;
  const scoreDiff = currentScore - previousScore;

  return (
    <div className="space-y-8 mt-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {/* Executive Transformation Header */}
      <div className="card border-brand-200 bg-gradient-to-r from-brand-600 to-indigo-700 p-8 shadow-xl shadow-brand-100 relative overflow-hidden">
        <div className="absolute top-0 right-0 p-12 opacity-10">
          <Verified className="h-32 w-32 text-white" />
        </div>
        
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-8">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2 py-0.5 bg-white/20 text-white text-[10px] font-black uppercase tracking-widest rounded">Intelligence Report</span>
              <Verified className="h-4 w-4 text-emerald-400" />
            </div>
            <h2 className="text-3xl font-black text-white uppercase tracking-tighter leading-tight">
              Security Infrastructure Transformation
            </h2>
            <p className="text-brand-100 text-sm mt-1 max-w-md">
              Full comparative audit between initial discovery and current hardened state.
            </p>
          </div>

          <div className="flex items-center gap-6 divide-x divide-white/10">
            <div className="group relative text-center cursor-help">
              <p className="text-[10px] font-black text-white/60 uppercase tracking-widest mb-1">Baseline</p>
              <p className="text-2xl font-black text-white/80">{previousScore}</p>
              <div className="absolute top-full left-1/2 -translate-x-1/2 mt-2 hidden group-hover:block w-32 bg-surface-900 text-white text-[9px] px-2 py-1 rounded-lg shadow-xl z-50 text-center font-normal border border-surface-700 animate-in fade-in duration-200">
                Score at the start of monitoring.
              </div>
            </div>
            <div className="group relative pl-6 text-center cursor-help">
              <p className="text-[10px] font-black text-white/60 uppercase tracking-widest mb-1">Current</p>
              <p className="text-4xl font-black text-white leading-none">{currentScore}</p>
              <div className="absolute top-full left-1/2 -translate-x-1/2 mt-2 hidden group-hover:block w-32 bg-surface-900 text-white text-[9px] px-2 py-1 rounded-lg shadow-xl z-50 text-center font-normal border border-surface-700 animate-in fade-in duration-200">
                Latest audit performance.
              </div>
            </div>
            <div className="pl-6">
              <div className={cn("px-4 py-2 rounded-xl flex flex-col items-center gap-0.5 shadow-lg", 
                scoreDiff >= 0 ? "bg-emerald-500 text-white" : "bg-red-500 text-white"
              )}>
                <TrendingUp className="h-4 w-4" />
                <span className="text-lg font-black leading-none">{scoreDiff > 0 ? `+${scoreDiff}` : scoreDiff} PTS</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Comparative Dual Audit View */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8 items-start">
        {/* INITIAL POSTURE (BEFORE) */}
        <div className="space-y-4">
          <div className="flex items-center gap-3 px-2">
            <div className="p-2 bg-surface-100 text-surface-600 rounded-lg">
              <History className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-sm font-black text-surface-900 uppercase tracking-widest">Initial Audit Result</h3>
              <p className="text-[10px] text-surface-400 font-mono">Snapshot: {new Date(previous.scannedAt).toLocaleString()}</p>
            </div>
          </div>
          
          <div className="card border-surface-200 bg-surface-50/30 p-4 shadow-sm grayscale-[0.3]">
            <ScanResults 
              data={previous} 
              isRefreshing={false} 
              onRefresh={() => {}} 
              hideRefreshButton={true}
              isHistorical={true}
            />
          </div>
        </div>

        {/* CURRENT HARDENING (AFTER) */}
        <div className="space-y-4">
          <div className="flex items-center gap-3 px-2">
            <div className="p-2 bg-brand-100 text-brand-600 rounded-lg shadow-sm">
              <ShieldPlus className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-sm font-black text-brand-700 uppercase tracking-widest">Hardened Security Status</h3>
              <p className="text-[10px] text-brand-400 font-mono">Live Audit: {new Date(current.scannedAt).toLocaleString()}</p>
            </div>
          </div>

          <div className="card border-brand-200 bg-white p-4 shadow-xl shadow-brand-100 ring-2 ring-brand-500 ring-offset-4">
            <ScanResults 
              data={current} 
              isRefreshing={false} 
              onRefresh={() => {}} 
              hideRefreshButton={true}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
