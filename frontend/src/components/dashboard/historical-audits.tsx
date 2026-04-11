"use client";

import React from "react";
import { trpc } from "@/lib/trpc";
import { Spinner } from "@/components/ui/spinner";
import { Calendar, ChevronRight, Scale, Eye, TrendingUp, TrendingDown, Minus } from "lucide-react";
import { cn } from "@/lib/cn";

interface HistoricalAuditsProps {
  brandId: string;
  onViewScan: (scanId: string) => void;
  onCompareScan: (scanId: string) => void;
}

export function HistoricalAudits({ brandId, onViewScan, onCompareScan }: HistoricalAuditsProps) {
  const { data, isLoading, error } = trpc.scan.history.useQuery({
    brandId,
    limit: 50,
  });

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <Spinner size="lg" className="mb-4" />
        <p className="text-xs font-black uppercase tracking-widest text-surface-400">Loading History Timeline...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-8 text-center bg-red-50 rounded-2xl border border-red-100">
        <p className="text-red-600 font-bold">Failed to load history</p>
        <p className="text-xs text-red-500 mt-1">{error.message}</p>
      </div>
    );
  }

  const scans = data?.items || [];

  if (scans.length === 0) {
    return (
      <div className="p-12 text-center bg-surface-50 rounded-2xl border border-dashed border-surface-200">
        <Calendar className="h-10 w-10 text-surface-300 mx-auto mb-4" />
        <h3 className="text-lg font-bold text-surface-900 uppercase">No History Yet</h3>
        <p className="text-sm text-surface-500 mt-2">Historical data will appear here as you perform new audits.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-300">
      <div className="flex items-center justify-between px-2">
        <h2 className="text-sm font-black text-surface-900 uppercase tracking-widest flex items-center gap-2">
          <Calendar className="h-4 w-4 text-brand-600" />
          Audit Timeline
        </h2>
        <span className="text-[10px] font-bold text-surface-400 uppercase tracking-widest">
          {scans.length} Reports Found
        </span>
      </div>

      <div className="grid grid-cols-1 gap-3">
        {scans.map((scan, index) => {
          const score = scan.security?.score || 0;
          const prevScore = scans[index + 1]?.security?.score;
          const trend = prevScore !== undefined ? score - prevScore : 0;

          return (
            <div 
              key={scan.id} 
              className="card bg-white border-surface-200 p-4 hover:border-brand-300 transition-all group shadow-sm hover:shadow-md"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="flex items-center gap-4">
                  <div className={cn(
                    "h-12 w-12 rounded-xl flex items-center justify-center font-black text-lg",
                    score >= 90 ? "bg-emerald-50 text-emerald-600 border border-emerald-100" :
                    score >= 70 ? "bg-amber-50 text-amber-600 border border-amber-100" :
                    "bg-red-50 text-red-600 border border-red-100"
                  )}>
                    {score}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="font-black text-surface-900 uppercase tracking-tight leading-none mb-1">
                        {new Date(scan.createdAt).toLocaleDateString(undefined, { 
                          month: 'long', 
                          day: 'numeric', 
                          year: 'numeric' 
                        })}
                      </p>
                      {trend !== 0 && (
                        <div className={cn(
                          "flex items-center gap-0.5 text-[10px] font-black uppercase tracking-widest",
                          trend > 0 ? "text-emerald-500" : "text-red-500"
                        )}>
                          {trend > 0 ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
                          {Math.abs(trend)} pts
                        </div>
                      )}
                    </div>
                    <p className="text-[10px] font-mono text-surface-400">
                      ID: {scan.id.slice(0, 8)}... • {new Date(scan.createdAt).toLocaleTimeString()}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => onViewScan(scan.id)}
                    className="btn-outline h-9 px-4 text-[10px] font-black tracking-widest uppercase gap-2 hover:bg-surface-50"
                  >
                    <Eye className="h-3.5 w-3.5" />
                    View Details
                  </button>
                  <button
                    onClick={() => onCompareScan(scan.id)}
                    className="btn-primary h-9 px-4 text-[10px] font-black tracking-widest uppercase gap-2 shadow-md shadow-brand-100"
                  >
                    <Scale className="h-3.5 w-3.5" />
                    Compare
                  </button>
                  <ChevronRight className="h-5 w-5 text-surface-300 group-hover:text-brand-400 transition-colors hidden sm:block" />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
