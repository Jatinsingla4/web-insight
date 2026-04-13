"use client";

import React, { useEffect, useState } from "react";
import { trpc } from "@/lib/trpc";
import { ScanResults } from "@/components/scan/scan-results";
import { ScanComparison } from "@/components/scan/scan-comparison";
import { HistoricalAudits } from "@/components/dashboard/historical-audits";
import { Spinner } from "@/components/ui/spinner";
import { AlertCircle, RefreshCw, BarChart3, Globe, Trash2, Scale, History, ChevronLeft, Bell } from "lucide-react";
import { useRouter } from "next/navigation";
import { useRef } from "react";
import { MonitoringSettings } from "@/components/dashboard/monitoring-settings";

interface BrandDashboardProps {
  brandId: string;
  brandName: string;
  brandDomain: string;
}

export function BrandDashboard({ brandId, brandName, brandDomain }: BrandDashboardProps) {
  const [isScanning, setIsScanning] = useState(false);
  const [viewMode, setViewMode] = useState<"latest" | "compare" | "history" | "monitoring">("latest");
  const [compareScanId, setCompareScanId] = useState<string | null>(null);
  const [viewScanId, setViewScanId] = useState<string | null>(null);
  const printRef = useRef<HTMLDivElement>(null);
  
  const utils = trpc.useUtils();
  const router = useRouter();

  const deleteMutation = trpc.brand.delete.useMutation({
    onSuccess: () => {
      utils.brand.list.invalidate();
      router.push("/dashboard");
    },
  });

  const { data: compareData, refetch: refetchCompare } = trpc.scan.compare.useQuery(
    { brandId, previousScanId: compareScanId || undefined },
    { enabled: viewMode === "compare" }
  );

  const { data: latestScan, isLoading, error, refetch } = trpc.scan.getLatest.useQuery(
    { id: brandId },
    {
      // Poll if we are in a "Scanning" state or if no scan exists yet
      refetchInterval: (query) => {
        const data = query.state.data;
        if (isScanning || !data) return 5000; // Poll every 5s
        return false;
      },
      enabled: !viewScanId,
    }
  );

  const { data: historicalScan } = trpc.scan.getById.useQuery(
    { id: brandId, scanId: viewScanId! },
    { enabled: !!viewScanId }
  );

  const activeScan = viewScanId ? historicalScan : latestScan;

  const rescanMutation = trpc.scan.rescan.useMutation({
    onSuccess: () => {
      setIsScanning(true);
      // Invalidate both brand list and latest scan
      utils.brand.list.invalidate();
      refetch();
    },
  });

  // If we have a scan and its scannedAt is recent, we can stop the "isScanning" UI local state
  useEffect(() => {
    if (latestScan && isScanning) {
      const scanTime = new Date(latestScan.scannedAt).getTime();
      const now = new Date().getTime();
      // If scan was within last 30 seconds, it's likely the one we just triggered
      if (now - scanTime < 30000) {
        setIsScanning(false);
      }
    }
  }, [latestScan, isScanning]);

  const handleRescan = () => {
    rescanMutation.mutate({ brandId });
  };

  if (isLoading && !activeScan) {
    return (
      <div className="flex flex-col items-center justify-center py-20 animate-fade-in">
        <Spinner size="lg" className="mb-4" />
        <p className="text-surface-500 font-medium font-mono text-sm tracking-widest">INITIALIZING AUDIT ENGINE...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card p-8 border-red-100 bg-red-50/30 text-center animate-fade-in w-full">
        <AlertCircle className="h-10 w-10 text-red-500 mx-auto mb-4" />
        <h3 className="text-lg font-bold text-red-900 mb-2">FAILED TO RETRIEVE AUDIT</h3>
        <p className="text-red-700 text-sm mb-6">{error.message}</p>
        <button onClick={() => refetch()} className="btn-primary bg-red-600 hover:bg-red-700 border-red-700">
          RETRY CONNECTION
        </button>
      </div>
    );
  }

  if (!activeScan && viewMode !== "history") {
    return (
      <div className="card p-12 border-2 border-dashed border-surface-200 bg-surface-50/50 text-center animate-fade-in w-full">
        <div className="relative mb-6">
          <Globe className="h-12 w-12 text-brand-600 mx-auto animate-pulse" />
          <div className="absolute inset-0 h-12 w-12 border-2 border-brand-200 border-t-brand-600 rounded-full animate-spin mx-auto" />
        </div>
        <h3 className="text-lg font-bold text-surface-900 uppercase tracking-widest">Initial Audit in Progress</h3>
        <p className="text-sm text-surface-500 mb-8 leading-relaxed max-w-md mx-auto">
          We're currently performing a deep-scan of <span className="font-bold text-surface-900">{brandDomain}</span> to analyze your infrastructure and security posture. 
          Results will appear automatically in a moment.
        </p>
        <div className="flex flex-col items-center gap-4">
          <div className="flex items-center gap-2 text-brand-600 font-mono text-[10px] font-black uppercase tracking-widest">
            <Spinner size="sm" />
            Analyzing DNS Records...
          </div>
          <button 
            onClick={handleRescan}
            disabled={rescanMutation.isPending}
            className="btn-outline gap-2 px-6 text-[10px] font-black tracking-widest uppercase"
          >
            {rescanMutation.isPending ? <Spinner size="sm" /> : <RefreshCw className="h-3 w-3" />}
            Force Restart Scan
          </button>
          <button 
            onClick={() => {
              if (window.confirm(`Delete "${brandName}" and cancel initial audit?`)) {
                deleteMutation.mutate({ id: brandId });
              }
            }}
            disabled={deleteMutation.isPending}
            className="flex items-center gap-2 text-[10px] font-bold text-red-400 hover:text-red-500 transition-colors uppercase tracking-widest mt-2"
          >
            {deleteMutation.isPending ? <Spinner size="sm" /> : <Trash2 className="h-3 w-3" />}
            Cancel & Purge Brand
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fade-in" ref={printRef}>
      <div className="flex items-center justify-between gap-4 p-6 bg-white border border-surface-200 rounded-2xl shadow-sm" data-html2canvas-ignore>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-4 hidden print-header">
            <Globe className="h-7 w-7 text-brand-600" />
            <div>
              <h1 className="text-2xl font-black text-surface-900 uppercase tracking-tight leading-none mb-1">
                {brandName}
              </h1>
              <p className="text-sm font-mono text-brand-600 font-bold">{brandDomain}</p>
            </div>
          </div>
          <div className="h-14 w-14 rounded-2xl bg-brand-600 flex items-center justify-center text-white shadow-lg shadow-brand-100">
            <Globe className="h-7 w-7" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-black text-surface-900 uppercase tracking-tight leading-none">
                {brandName}
              </h1>
              {viewScanId && (
                <div className="group relative">
                  <div className="px-2 py-0.5 bg-amber-100 text-amber-700 text-[10px] font-black uppercase tracking-widest rounded flex items-center gap-1 cursor-help">
                    <History className="h-3 w-3" />
                    Reviewing History
                  </div>
                  <div className="absolute top-full left-0 mt-2 hidden group-hover:block w-48 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 font-normal border border-surface-700 animate-in fade-in duration-200">
                    You are viewing a past snapshot. Some real-time metrics may have changed.
                  </div>
                </div>
              )}
            </div>
            <p className="text-sm font-mono text-brand-600 font-bold">{brandDomain}</p>
          </div>
        </div>
        
        <div className="flex flex-col items-end gap-1">
          <div className="flex items-center gap-3">
             {viewScanId ? (
               <button
                 onClick={() => setViewScanId(null)}
                 className="btn-outline h-10 px-4 text-[11px] font-black tracking-widest gap-2 bg-amber-50 border-amber-200 text-amber-700"
               >
                 <ChevronLeft className="h-4 w-4" />
                 BACK TO LATEST
               </button>
             ) : (
               <>
                 {isScanning && (
                   <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-brand-50 text-brand-700 text-xs font-black animate-pulse border border-brand-100">
                     <RefreshCw className="h-3 w-3 animate-spin" />
                     POD SCANNING...
                   </div>
                 )}
                 <div className="group relative">
                   <button
                     onClick={handleRescan}
                     disabled={isScanning || rescanMutation.isPending}
                     className="btn-primary h-10 px-4 text-[11px] font-black tracking-widest gap-2 shadow-md shadow-brand-100 disabled:opacity-50"
                   >
                     {(rescanMutation.isPending) ? (
                       <Spinner size="sm" />
                     ) : (
                       <RefreshCw className={`h-3.5 w-3.5 ${isScanning ? 'animate-spin' : ''}`} />
                     )}
                     {isScanning ? 'IN PROGRESS' : 'TRIGGER NEW SCAN'}
                   </button>
                   <div className="absolute top-full left-1/2 -translate-x-1/2 mt-2 hidden group-hover:block w-48 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 text-center font-normal border border-surface-700 animate-in fade-in duration-200">
                     Run a fresh, deep-scan of your infrastructure to detect recent changes.
                   </div>
                 </div>
               </>
             )}

              <div className="group relative">
                <button
                  onClick={() => {
                    if (viewMode === "history") {
                      setViewMode("latest");
                    } else {
                      setViewMode("history");
                    }
                  }}
                  className={`btn-outline h-10 px-4 text-[11px] font-black tracking-widest gap-2 shadow-sm transition-all focus:ring-0 ${viewMode === "history" ? "bg-brand-50 border-brand-200 text-brand-700" : ""}`}
                >
                  <History className="h-4 w-4" />
                  HISTORY & TIMELINE
                </button>
                <div className="absolute top-full left-1/2 -translate-x-1/2 mt-2 hidden group-hover:block w-48 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 text-center font-normal border border-surface-700 animate-in fade-in duration-200">
                  View all past audits and track your security progress over time.
                </div>
              </div>

              <div className="group relative">
                <button
                  onClick={() => {
                    if (viewMode === "compare") {
                      setViewMode("latest");
                      setCompareScanId(null);
                    } else {
                      setViewMode("compare");
                      refetchCompare();
                    }
                  }}
                  className={`btn-outline h-10 px-4 text-[11px] font-black tracking-widest gap-2 shadow-sm transition-all focus:ring-0 ${viewMode === "compare" ? "bg-brand-50 border-brand-200 text-brand-700" : ""}`}
                >
                  <Scale className="h-4 w-4" />
                  {viewMode === "compare" ? "SHOW LATEST SCAN" : "COMPARATIVE ANALYSIS"}
                </button>
                <div className="absolute top-full right-0 mt-2 hidden group-hover:block w-56 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 text-center font-normal border border-surface-700 animate-in fade-in duration-200">
                  Compare current results with previous audits to verify security hardening.
                </div>
              </div>

              <div className="group relative">
                <button
                  onClick={() => {
                    if (viewMode === "monitoring") {
                      setViewMode("latest");
                    } else {
                      setViewMode("monitoring");
                    }
                  }}
                  className={`btn-outline h-10 px-4 text-[11px] font-black tracking-widest gap-2 shadow-sm transition-all focus:ring-0 ${viewMode === "monitoring" ? "bg-brand-50 border-brand-200 text-brand-700" : ""}`}
                >
                  <Bell className="h-4 w-4" />
                  ALERTS & MONITORING
                </button>
                <div className="absolute top-full right-0 mt-2 hidden group-hover:block w-56 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 text-center font-normal border border-surface-700 animate-in fade-in duration-200">
                  Configure proactive email alerts for SSL certificate expirations.
                </div>
              </div>
             <button
               onClick={() => {
                 if (window.confirm(`CRITICAL: Purge "${brandName}" and all associated data permanently?`)) {
                   deleteMutation.mutate({ id: brandId });
                 }
               }}
               disabled={deleteMutation.isPending}
               className="btn-outline border-red-100 text-red-500 hover:bg-red-50 hover:border-red-200 h-10 px-3 transition-all"
               title="Delete Brand"
             >
               {deleteMutation.isPending ? <Spinner size="sm" /> : <Trash2 className="h-4 w-4" />}
             </button>
          </div>
          <p className="text-[10px] text-surface-400 font-bold uppercase tracking-widest">
            {viewScanId ? "Viewing Archive" : "Last Audit"}: {activeScan ? new Date(activeScan.scannedAt).toLocaleString() : "Never"}
          </p>
        </div>
      </div>

      {viewMode === "history" ? (
        <HistoricalAudits 
          brandId={brandId} 
          onViewScan={(id) => {
            setViewScanId(id);
            setViewMode("latest");
          }}
          onCompareScan={(id) => {
            setCompareScanId(id);
            setViewMode("compare");
            refetchCompare();
          }}
        />
      ) : viewMode === "compare" ? (
        compareData && compareData.current ? (
          <ScanComparison current={compareData.current} previous={compareData.previous} />
        ) : (
          <div className="flex flex-col items-center justify-center py-20">
            <Spinner size="lg" />
            <p className="mt-4 text-xs font-black uppercase tracking-widest text-surface-400">Loading Intelligence...</p>
          </div>
        )
      ) : viewMode === "monitoring" ? (
        <MonitoringSettings 
          domain={brandDomain} 
          expiryDate={activeScan?.ssl?.validTo || new Date().toISOString()} 
        />
      ) : (
        <ScanResults 
          data={activeScan!} 
          isRefreshing={isScanning} 
          onRefresh={handleRescan}
          showSaveBrandButton={false} 
          hideRefreshButton={true}
        />
      )}
    </div>
  );
}
