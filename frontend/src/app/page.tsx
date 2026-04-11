"use client";

import { useState, useEffect } from "react";
import { Navbar } from "@/components/dashboard/navbar";
import { QuickScanForm } from "@/components/scan/quick-scan-form";
import { useAuthStore } from "@/lib/auth-store";
import { useRouter } from "next/navigation";
import { Shield, Zap, Clock, BarChart3, ArrowLeft } from "lucide-react";

export default function HomePage() {
  const { isAuthenticated } = useAuthStore();
  const router = useRouter();
  const [hasScanResults, setHasScanResults] = useState(false);
  const [triggerUrl, setTriggerUrl] = useState<string | null>(null);

  useEffect(() => {
    if (isAuthenticated) {
      router.replace("/dashboard");
    }
  }, [isAuthenticated, router]);

  return (
    <div className="min-h-screen bg-surface-50">
      <Navbar />

      <main className="w-full px-2 sm:px-4 lg:px-6 py-8 md:py-16">
        {/* Quick Scan Section */}
        <section className={hasScanResults ? "mb-6" : "mb-16"}>
          <div className="mb-6 text-left">
            <h2 className="text-4xl font-black text-surface-900 uppercase tracking-tighter mb-4">
              {isAuthenticated ? "Redirecting to Fleets..." : "Instant Domain Intelligence"}
            </h2>
            <p className="text-lg text-surface-500 font-medium leading-relaxed">
              {isAuthenticated 
                ? "Attuning to your secure monitoring hub. You'll be redirected in a moment."
                : "Analyze DNS health, security posture, and infrastructure drift in real-time. No registration required for guest audits."}
            </p>
          </div>
          
           <div className="card p-8 md:p-12 shadow-2xl border-t-8 border-t-brand-600 bg-white/50 backdrop-blur-md w-full mt-12">
             <QuickScanForm 
               onScanStateChange={setHasScanResults} 
               triggerUrl={triggerUrl}
             />
           </div>

            {hasScanResults && (
              <div className="mt-8 flex justify-center">
                <button 
                  onClick={() => {
                    setHasScanResults(false);
                    setTriggerUrl(null);
                  }}
                  className="btn-secondary gap-2 px-8 py-3 rounded-full shadow-lg hover:shadow-xl transition-all uppercase tracking-[0.2em] text-[11px] font-black"
                >
                  <ArrowLeft className="h-4 w-4" />
                  Reset Audit Tool
                </button>
              </div>
            )}
         </section>

        {/* Feature Section - Guest View */}
        {!hasScanResults && !isAuthenticated && (
           <section className="card p-12 bg-surface-900 text-white overflow-hidden relative animate-in fade-in zoom-in duration-700">
             <div className="absolute top-0 right-0 p-12 opacity-5">
               <Shield className="h-64 w-64" />
             </div>
             <div className="text-center max-w-3xl mx-auto relative z-10">
               <h2 className="text-3xl font-black mb-6 uppercase tracking-tight">
                 Professional Fleet Monitoring
               </h2>
               <p className="text-surface-400 mb-12 text-lg font-medium leading-relaxed">
                 Aggregate and monitor your entire infrastructure. Sign in with Google to track domain asset health, detect security configuration drift, and receive automated risk intelligence reports.
               </p>
               <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
                 <Feature
                   icon={<Zap className="h-7 w-7" />}
                   label="High-Frequency Scans"
                 />
                 <Feature
                   icon={<Clock className="h-7 w-7" />}
                   label="Fleet Governance"
                 />
                 <Feature
                   icon={<BarChart3 className="h-7 w-7" />}
                   label="Infrastructure Drift"
                 />
               </div>
             </div>
           </section>
        )}
      </main>

      <footer className="border-t border-surface-200 mt-20 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
          <div className="flex flex-col items-center justify-center gap-6">
            <div className="flex items-center gap-2 grayscale opacity-30">
              <Shield className="h-6 w-6" />
              <span className="font-black text-lg tracking-tighter uppercase">WEB INSIGHT</span>
            </div>
            <p className="text-[11px] font-black text-surface-400 uppercase tracking-[0.3em] text-center" suppressHydrationWarning>
              &copy; {new Date().getFullYear()} Infrastructure & Health Intelligence.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

function Feature({ icon, label }: { icon: React.ReactNode; label: string }) {
  return (
    <div className="flex flex-col items-center gap-4 p-6 rounded-2xl bg-white/5 border border-white/10 backdrop-blur-md transition-all hover:bg-white/10 hover:-translate-y-1">
      <div className="text-brand-400">{icon}</div>
      <span className="text-[11px] font-black uppercase tracking-widest text-brand-100">{label}</span>
    </div>
  );
}
