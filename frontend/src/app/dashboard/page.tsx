"use client";

import { useState } from "react";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Navbar } from "@/components/dashboard/navbar";
import { useAuthStore } from "@/lib/auth-store";
import { useSearchParams } from "next/navigation";
import { BrandDashboard } from "@/components/dashboard/brand-dashboard";
import { trpc } from "@/lib/trpc";
import type { Brand } from "@dns-checker/shared";
import { QuickScanForm } from "@/components/scan/quick-scan-form";
import { BrandManagement } from "@/components/dashboard/brand-management";
import { AlertCircle, Zap, Shield, LayoutGrid, Plus } from "lucide-react";

import { Suspense } from "react";

function DashboardContent() {
  const { isAuthenticated } = useAuthStore();
  const router = useRouter();
  const searchParams = useSearchParams();
  const brandsQuery = trpc.brand.list.useQuery({ limit: 100 }, { enabled: !!isAuthenticated });
  
  const brandId = searchParams.get("brandId");
  const mode = searchParams.get("mode");
  const selectedBrand = brandsQuery.data?.items.find((b: Brand) => b.id === brandId);

  useEffect(() => {
    if (!isAuthenticated) {
      router.replace("/");
    }
  }, [isAuthenticated, router]);

  if (!isAuthenticated) return null;

  return (
    <div className="min-h-screen bg-surface-50 flex flex-col">
      <Navbar />
      <div className="flex flex-1 flex-col overflow-hidden">
         {/* Main Workspace Area - No Sidebar */}
        <main className="flex-1 overflow-y-auto px-2 sm:px-4 lg:px-6 xl:px-4 py-8 md:py-12">
          <div className="w-full relative h-full animate-in fade-in duration-500">
             {mode === "manage" ? (
               <BrandManagement />
             ) : mode === "quick" ? (
               <div className="w-full space-y-8">
                 <div className="mb-10 text-center xl:text-left">
                   <div className="flex flex-col xl:flex-row xl:items-center gap-6">
                     <div className="h-14 w-14 rounded-2xl bg-brand-600 flex items-center justify-center shadow-xl shadow-brand-100 rotate-3 transition-transform hover:rotate-12 duration-500 mx-auto xl:mx-0 shrink-0">
                       <Zap className="h-7 w-7 text-white" />
                     </div>
                     <div>
                       <h2 className="text-4xl font-black text-surface-900 uppercase tracking-tighter">Instant Analysis</h2>
                       <p className="text-surface-500 font-medium text-lg italic">Perform a stateless deep-scan on any domain asset in real-time.</p>
                     </div>
                   </div>
                 </div>
                 <div className="card p-4 md:p-6 lg:p-8 shadow-2xl border-surface-200/60 bg-white/50 backdrop-blur-md w-full">
                   <QuickScanForm onScanStateChange={() => {}} />
                 </div>
               </div>
             ) : brandId ? (
               selectedBrand ? (
                 <BrandDashboard 
                   brandId={selectedBrand.id}
                   brandName={selectedBrand.name} 
                   brandDomain={selectedBrand.domain} 
                 />
               ) : brandsQuery.isLoading ? (
                 <div className="flex flex-col items-center justify-center py-32 animate-pulse">
                   <div className="h-12 w-12 rounded-full border-4 border-brand-100 border-t-brand-600 animate-spin mb-4" />
                   <p className="text-surface-400 font-mono text-[11px] font-black uppercase tracking-widest italic">Attuning to Domain Frequency...</p>
                 </div>
               ) : (
                 <div className="max-w-2xl mx-auto card p-12 text-center border-red-100 bg-red-50/20 shadow-2xl shadow-red-100/20">
                   <AlertCircle className="h-12 w-12 text-red-500 mx-auto mb-6" />
                   <h3 className="text-xl font-bold text-red-900 mb-2 uppercase tracking-tighter">Domain Access Revoked</h3>
                   <p className="text-red-700 text-sm mb-8 leading-relaxed font-medium">The domain asset you're trying to reach has been purged from our fleet or you no longer have the required monitoring permissions.</p>
                   <button onClick={() => router.push('/dashboard')} className="btn-primary bg-red-600 hover:bg-red-700 border-red-700 h-11 px-10 text-[11px] font-black tracking-widest transition-all">
                     RETURN TO SECURITY HUB
                   </button>
                 </div>
               )
             ) : (
               /* Default to Portfolio Management when no brand is selected */
               <BrandManagement />
             )}
          </div>
        </main>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-surface-50 flex items-center justify-center">
        <div className="flex flex-col items-center animate-pulse">
          <div className="h-12 w-12 rounded-full border-4 border-brand-100 border-t-brand-600 animate-spin mb-4" />
          <p className="text-surface-400 font-mono text-[11px] font-black uppercase tracking-widest leading-tight text-center">
            Synchronizing Security Context...
          </p>
        </div>
      </div>
    }>
      <DashboardContent />
    </Suspense>
  );
}
