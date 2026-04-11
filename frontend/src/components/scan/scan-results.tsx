"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import { 
  Globe, 
  Search, 
  AlertCircle, 
  Bell, 
  Mail, 
  Bookmark, 
  Check, 
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldEllipsis,
  Database,
  Cpu,
  Server,
  Monitor,
  ArrowRight,
  Zap,
  HelpCircle
} from "lucide-react";
import { trpc } from "@/lib/trpc";
import { useAuthStore } from "@/lib/auth-store";
import type { ScanResult } from "@dns-checker/shared";
import { Spinner } from "@/components/ui/spinner";
import { CollapsibleSection } from "@/components/ui/collapsible-section";
import { cn } from "@/lib/cn";

export interface ScanResultsProps {
  data: ScanResult;
  isRefreshing: boolean;
  onRefresh: () => void;
  showSaveBrandButton?: boolean;
  hideRefreshButton?: boolean;
  isHistorical?: boolean;
  isAuthenticated?: boolean;
}

/** Simulated progress: eases 0→88% over ~90s, then pulses 88-96% while waiting, snaps to 100 on done. */
function useDeepScanProgress(status: string | undefined): { progress: number; isStalled: boolean } {
  const [progress, setProgress] = useState(0);
  const [isStalled, setIsStalled] = useState(false);
  const startTimeRef = useRef(Date.now());

  useEffect(() => {
    if (status === "ready" || status === "failed") {
      setProgress(100);
      setIsStalled(false);
      return;
    }
    if (status !== "scanning") {
      setProgress(0);
      setIsStalled(false);
      return;
    }

    startTimeRef.current = Date.now();
    setProgress(5);
    setIsStalled(false);

    const interval = setInterval(() => {
      const elapsed = (Date.now() - startTimeRef.current) / 1000;

      if (elapsed < 90) {
        // Phase 1: Smooth ease-out to 88%
        const p = 5 + 83 * (1 - Math.exp(-elapsed / 35));
        setProgress(Math.round(p));
      } else {
        // Phase 2: Gentle pulse between 88-96% so it doesn't look frozen
        const wave = Math.sin((elapsed - 90) / 8) * 4; // oscillates ±4
        setProgress(Math.round(92 + wave));
      }

      // After 2.5 min, show "taking longer" message
      if (elapsed > 150) {
        setIsStalled(true);
      }
    }, 500);

    return () => clearInterval(interval);
  }, [status]);

  return { progress, isStalled };
}

export function ScanResults({
  data,
  isRefreshing,
  onRefresh,
  showSaveBrandButton = false,
  hideRefreshButton = false,
  isHistorical = false,
}: ScanResultsProps) {
  const { isAuthenticated } = useAuthStore();
  const [reminderSet, setReminderSet] = useState(false);
  const [liveSSL, setLiveSSL] = useState(data.ssl);

  // Poll for deep scan updates when status is "scanning"
  const sslStatusQuery = trpc.scan.sslStatus.useQuery(
    { domain: data.domain },
    {
      enabled: !!data.ssl && liveSSL?.deepScanStatus === "scanning",
      refetchInterval: 15000, // Poll every 15s
      refetchIntervalInBackground: false,
    }
  );

  // Update liveSSL when poll returns new data
  useEffect(() => {
    if (sslStatusQuery.data) {
      setLiveSSL(sslStatusQuery.data);
    }
  }, [sslStatusQuery.data]);

  // Reset liveSSL when scan data changes (new scan)
  useEffect(() => {
    setLiveSSL(data.ssl);
  }, [data.ssl]);

  // Use liveSSL for display (falls back to initial data.ssl)
  const displaySSL = liveSSL ?? data.ssl;
  const { progress: deepScanProgress, isStalled: deepScanStalled } = useDeepScanProgress(displaySSL?.deepScanStatus);

  const reminderMutation = trpc.reminder.setSslReminder.useMutation({
    onSuccess: () => {
      setReminderSet(true);
    },
  });
 
  const [brandSaved, setBrandSaved] = useState(false);
  const utils = trpc.useUtils();
 
  const saveBrandMutation = trpc.brand.create.useMutation({
    onSuccess: () => {
      setBrandSaved(true);
      utils.brand.invalidate();
    },
  });
 
  return (
    <div className={cn("space-y-6 animate-fade-in", isHistorical && "opacity-90")}>
      <div className={cn(
        "flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4",
        isHistorical ? "border-surface-200" : "border-surface-100"
      )}>
        <div className="flex items-center gap-3">
          {isHistorical && (
            <div className="px-2 py-0.5 bg-surface-200 text-surface-600 text-[10px] font-black uppercase tracking-widest rounded-md">
              Historical Audit
            </div>
          )}
          <h2 className={cn("text-lg font-semibold", isHistorical ? "text-surface-500" : "text-surface-900")}>
            Results for {data.domain}
          </h2>
          <span className="text-xs text-surface-400" suppressHydrationWarning>
            {isHistorical ? "Captured " : "Scanned "} {new Date(data.scannedAt).toLocaleString()}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {isAuthenticated && showSaveBrandButton && (
            <button
              onClick={() => saveBrandMutation.mutate({ 
                domain: data.domain, 
                name: data.domain,
                initialScanData: data 
              })}
              disabled={saveBrandMutation.isPending || brandSaved}
              className={`btn-outline text-xs h-8 gap-2 bg-white ${
                brandSaved ? 'text-emerald-600 border-emerald-200 bg-emerald-50' : 'text-brand-600 border-brand-200'
              }`}
            >
              {saveBrandMutation.isPending ? (
                <Spinner size="sm" />
              ) : brandSaved ? (
                <Check className="h-3 w-3" />
              ) : (
                <Bookmark className="h-3 w-3" />
              )}
              {brandSaved ? "Saved to Brands" : "Save to My Brands"}
            </button>
          )}
          {!hideRefreshButton && (
            <button
              onClick={onRefresh}
              disabled={isRefreshing}
              className="btn-outline text-xs h-8 gap-2 bg-white"
            >
              {isRefreshing ? (
                <Spinner size="sm" />
              ) : (
                <RefreshCw className="h-3 w-3" />
              )}
              {isRefreshing ? "Scanning..." : "RESCAN"}
            </button>
          )}
        </div>
      </div>

      {/* Risk Exposure & Cookie Audit */}
      {((data.vulnerabilityExposure?.length ?? 0) > 0 || (data.cookieAudit?.length ?? 0) > 0) && (
        <CollapsibleSection
          title="Critical Risk & Session Audit"
          subtitle="Analysis of exposed sensitive files and session cookie security configurations."
          icon={<ShieldAlert className="h-5 w-5 text-red-500" />}
          defaultExpanded={data.vulnerabilityExposure?.some(v => v.status === 'exposed') ?? true}
          badge={
            data.vulnerabilityExposure && (
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-widest ${
                data.vulnerabilityExposure.some(v => v.status === 'exposed') 
                  ? 'bg-red-100 text-red-600 animate-pulse' 
                  : 'bg-emerald-100 text-emerald-600'
              }`}>
                {data.vulnerabilityExposure.some(v => v.status === 'exposed') ? 'Attention Required' : 'Secure'}
              </span>
            )
          }
          className="border-l-4 border-l-red-500 bg-white"
        >
          <div className="space-y-8">
            {/* File Exposures */}
            {data.vulnerabilityExposure && data.vulnerabilityExposure.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <p className="text-[10px] font-bold text-surface-400 uppercase tracking-widest leading-none">
                    Sensitive File Exposure
                  </p>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {data.vulnerabilityExposure.map((vuln) => (
                    <div key={vuln.path} className="flex flex-col gap-2 w-full">
                      <div 
                        className={`group relative flex items-center justify-between gap-2 px-3 py-2.5 rounded-xl border text-xs font-medium cursor-help transition-all hover:shadow-md ${
                          vuln.status === 'exposed' 
                            ? 'border-red-200 bg-white text-red-700 shadow-sm shadow-red-50' 
                            : vuln.status === 'secure'
                              ? 'border-green-100 bg-white text-green-700'
                              : 'border-surface-200 bg-surface-50 text-surface-500'
                        }`}
                      >
                        <div className="flex items-center gap-2 overflow-hidden">
                          <span className="font-mono truncate">{vuln.path}</span>
                        </div>
                        <span className={`shrink-0 px-1.5 py-0.5 rounded text-[9px] uppercase font-bold ${
                          vuln.status === 'exposed' ? 'bg-red-600 text-white' : vuln.status === 'secure' ? 'bg-green-600 text-white' : 'bg-surface-500 text-white'
                        }`}>
                          {vuln.status}
                        </span>

                        {/* Tooltip */}
                        <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block w-56 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 text-center animate-in fade-in zoom-in duration-200 border border-surface-700 font-normal">
                          <p className="leading-relaxed">
                            {vuln.path.includes('.git') && "Critical: Exposed Git directory allows attackers to download your entire source code and developer history."}
                            {vuln.path.includes('.env') && "Critical: Environment files often contain database passwords, API keys, and sensitive secret tokens."}
                            {vuln.path.includes('security.txt') && "Security standard: A file for researchers to report vulnerabilities responsibly."}
                            {vuln.path.includes('.ds_store') && "Metadata risk: Reveals filenames and directory structure to potential attackers."}
                            {(!vuln.path.includes('.git') && !vuln.path.includes('.env') && !vuln.path.includes('security.txt') && !vuln.path.includes('.ds_store')) && vuln.description}
                          </p>
                        </div>
                      </div>
                      {vuln.status === 'exposed' && <SolutionBlock solution={vuln.solution} />}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Cookie Audit */}
            {data.cookieAudit && data.cookieAudit.length > 0 && (
              <div className="pt-6 border-t border-surface-200/50">
                <p className="text-[10px] font-bold text-surface-400 uppercase tracking-widest mb-3">
                  Session Cookie Security
                </p>
                <div className="overflow-x-auto -mx-6 px-6">
                  <table className="w-full text-[11px] min-w-[600px]">
                    <thead>
                      <tr className="text-surface-500 border-b border-surface-200">
                        <th className="text-left pb-3 font-semibold uppercase tracking-wider">Cookie Name</th>
                        <th className="text-center pb-3 font-semibold uppercase tracking-wider">
                          <div className="group relative flex items-center justify-center gap-1 cursor-help">
                            HttpOnly <span className="text-[10px] opacity-40">?</span>
                            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block w-40 bg-surface-900 text-white text-[10px] px-2 py-1.5 rounded-lg shadow-xl z-50 text-center font-normal">
                              Prevents JavaScript from accessing the cookie, mitigating Cross-Site Scripting (XSS).
                            </div>
                          </div>
                        </th>
                        <th className="text-center pb-3 font-semibold uppercase tracking-wider">
                          <div className="group relative flex items-center justify-center gap-1 cursor-help">
                            Secure <span className="text-[10px] opacity-40">?</span>
                            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block w-40 bg-surface-900 text-white text-[10px] px-2 py-1.5 rounded-lg shadow-xl z-50 text-center font-normal">
                              Ensures the cookie is only sent over encrypted HTTPS connections.
                            </div>
                          </div>
                        </th>
                        <th className="text-center pb-3 font-semibold uppercase tracking-wider">
                          <div className="group relative flex items-center justify-center gap-1 cursor-help">
                            SameSite <span className="text-[10px] opacity-40">?</span>
                            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block w-40 bg-surface-900 text-white text-[10px] px-2 py-1.5 rounded-lg shadow-xl z-50 text-center font-normal">
                              Controls cross-site request behavior to protect against CSRF attacks.
                            </div>
                          </div>
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-surface-100">
                      {data.cookieAudit.map((cookie) => (
                        <React.Fragment key={cookie.name}>
                          <tr className="hover:bg-surface-50/50 transition-colors">
                            <td className="py-3 font-medium text-surface-700 truncate max-w-[200px]">{cookie.name}</td>
                            <td className="py-3 text-center">
                              {cookie.isHttpOnly ? (
                                <span className="text-green-600 font-bold bg-green-50 px-2 py-1 rounded-lg text-[10px]">PASS</span>
                              ) : (
                                <span className="text-red-500 font-bold bg-red-50 px-2 py-1 rounded-lg text-[10px]">FAIL</span>
                              )}
                            </td>
                            <td className="py-3 text-center">
                              {cookie.isSecure ? (
                                <span className="text-green-600 font-bold bg-green-50 px-2 py-1 rounded-lg text-[10px]">PASS</span>
                              ) : (
                                <span className="text-red-500 font-bold bg-red-50 px-2 py-1 rounded-lg text-[10px]">FAIL</span>
                              )}
                            </td>
                            <td className="py-3 text-center">
                              <span className={`px-2 py-1 rounded-lg text-[10px] font-bold uppercase ${
                                cookie.sameSite ? 'bg-indigo-50 text-indigo-600' : 'bg-surface-100 text-surface-400'
                              }`}>
                                {cookie.sameSite || 'None'}
                              </span>
                            </td>
                          </tr>
                          {cookie.recommendation && (!cookie.isHttpOnly || !cookie.isSecure || !cookie.sameSite) && (
                            <tr>
                              <td colSpan={4} className="pb-4 pt-0">
                                <SolutionBlock solution={cookie.recommendation} title="Action Needed" />
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </CollapsibleSection>

      )}

      {/* Privacy Governance & Compliance */}
      {data.privacyAudit && (
        <CollapsibleSection
          title="Privacy Governance & Compliance"
          subtitle="Evaluation of tracking infrastructure and legal documentation posture (GDPR/CCPA ready)."
          icon={<ShieldCheck className="h-5 w-5 text-sky-500" />}
          defaultExpanded={!data.privacyAudit.hasPrivacyPolicy || !data.privacyAudit.hasTermsOfService}
          badge={
            <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-widest ${
              (data.privacyAudit.hasPrivacyPolicy && data.privacyAudit.hasTermsOfService)
                ? 'bg-emerald-100 text-emerald-600' : 'bg-amber-100 text-amber-600'
            }`}>
              {(data.privacyAudit.hasPrivacyPolicy && data.privacyAudit.hasTermsOfService) ? 'Compliant' : 'Missing Documents'}
            </span>
          }
          className="border-l-4 border-l-sky-500 bg-white"
        >
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div className="group relative flex flex-col justify-center p-5 rounded-2xl bg-white border border-surface-200 cursor-help shadow-sm hover:shadow-md transition-all">
              <span className="text-xs font-bold text-surface-700 flex items-center gap-1 uppercase tracking-wider mb-4">
                Legal Compliance Status <span className="text-[10px] opacity-40">?</span>
              </span>
              <div className="flex gap-3">
                <div className={cn(
                  "flex-1 flex flex-col items-center gap-2 p-3 rounded-xl border transition-colors",
                  data.privacyAudit.hasPrivacyPolicy ? "bg-emerald-50/50 border-emerald-100" : "bg-red-50/50 border-red-100"
                )}>
                  <span className={cn("text-[10px] font-black uppercase tracking-widest", data.privacyAudit.hasPrivacyPolicy ? "text-emerald-700" : "text-red-700")}>Privacy Policy</span>
                  <span className={cn("text-lg font-bold", data.privacyAudit.hasPrivacyPolicy ? "text-emerald-600" : "text-red-600")}>
                    {data.privacyAudit.hasPrivacyPolicy ? '✓' : '✗'}
                  </span>
                </div>
                <div className={cn(
                  "flex-1 flex flex-col items-center gap-2 p-3 rounded-xl border transition-colors",
                  data.privacyAudit.hasTermsOfService ? "bg-emerald-50/50 border-emerald-100" : "bg-red-50/50 border-red-100"
                )}>
                  <span className={cn("text-[10px] font-black uppercase tracking-widest", data.privacyAudit.hasTermsOfService ? "text-emerald-700" : "text-red-700")}>Terms of Service</span>
                  <span className={cn("text-lg font-bold", data.privacyAudit.hasTermsOfService ? "text-emerald-600" : "text-red-600")}>
                    {data.privacyAudit.hasTermsOfService ? '✓' : '✗'}
                  </span>
                </div>
              </div>
              <div className="absolute right-0 bottom-full mb-2 hidden group-hover:block w-64 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 text-center font-normal border border-surface-700 animate-in fade-in duration-200">
                Determines if your essential legal disclosures are detectable, which is critical for trust and regulatory compliance.
              </div>
            </div>

            <div className="group relative p-5 rounded-2xl bg-white border border-surface-200 cursor-help shadow-sm hover:shadow-md transition-all">
              <p className="text-[10px] font-black text-surface-400 uppercase tracking-widest mb-4 flex items-center gap-1">
                Tracking Infrastructure <span className="text-[10px] opacity-40">?</span>
              </p>
              {data.privacyAudit.trackingPixels.length === 0 ? (
                <div className="flex items-center gap-2 text-emerald-600 bg-emerald-50 p-4 rounded-xl border border-emerald-100">
                  <Check className="h-4 w-4" />
                  <p className="text-xs font-bold uppercase tracking-tight">Privacy-First: No third-party pixels detected.</p>
                </div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {data.privacyAudit.trackingPixels.map((pixel, i) => (
                    <span key={i} className="px-3 py-1.5 rounded-xl bg-surface-50 text-surface-700 text-[10px] font-black border border-surface-100">
                      {pixel}
                    </span>
                  ))}
                </div>
              )}
              <div className="absolute right-0 bottom-full mb-2 hidden group-hover:block w-64 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 text-center font-normal border border-surface-700 animate-in fade-in duration-200">
                Detects marketing trackers that may collect user data. High pixel counts can increase "privacy debt" and slow down your site.
              </div>
            </div>
          </div>
        </CollapsibleSection>
      )}

      {/* DNS Records & Security Audit */}
      <CollapsibleSection
        title="DNS Records & Security Audit"
        subtitle="Verification of the Internet's Phonebook settings, including anti-spoofing and cryptographic signatures."
        icon={<Database className="h-5 w-5 text-blue-500" />}
        defaultExpanded={!(data.dns.records.some(r => r.data.toLowerCase().includes('v=spf1')) && data.dns.records.some(r => r.data.toLowerCase().includes('v=dmarc1')))}
        badge={
          data.dns.records.length > 0 && (
            <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-widest ${
              data.dns.records.some(r => r.data.toLowerCase().includes('v=spf1')) && data.dns.records.some(r => r.data.toLowerCase().includes('v=dmarc1'))
                ? 'bg-emerald-100 text-emerald-600' : 'bg-amber-100 text-amber-600'
            }`}>
              {data.dns.records.some(r => r.data.toLowerCase().includes('v=spf1')) && data.dns.records.some(r => r.data.toLowerCase().includes('v=dmarc1')) ? 'Active' : 'Partially Configured'}
            </span>
          )
        }
        className="border-l-4 border-l-blue-500 bg-white"
      >
        <div className="flex flex-col xl:flex-row gap-8 mb-8">
          <div className="flex-1">
            <p className="text-xs text-surface-500 leading-relaxed mb-4">
              DNS (Domain Name System) acts as the "Internet's Phonebook," translating domain names into IP addresses. 
              Our audit verifies both the delivery infrastructure and advanced security protocols like anti-spoofing and cryptographic signatures.
            </p>
            {data.dns.nameservers.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {data.dns.nameservers.map((ns, i) => (
                  <div key={i} className="group relative flex items-center gap-2 text-[10px] font-bold text-blue-600 bg-blue-100/50 px-3 py-1 rounded-lg cursor-help transition-all hover:bg-blue-100">
                    NS/TRUTH: {ns.toUpperCase()}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* DNS Security Audit: SPF, DMARC, DNSSEC, BIMI */}
        <div className="mb-8 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { 
              label: 'SPF Status', 
              key: 'v=spf1', 
              desc: 'Authorizes specific mail servers to send emails on your domain\'s behalf, preventing spoofing.' 
            },
            { 
              label: 'DMARC Policy', 
              key: 'v=DMARC1', 
              desc: 'Instructs receiving servers how to handle emails that fail SPF/DKIM checks (Monitor, Quarantine, or Reject).' 
            },
            { 
              label: 'DNSSEC Status', 
              key: 'dnssec', 
              desc: 'Adds cryptographic signatures to DNS records to ensure they haven\'t been tampered with (prevents Cache Poisoning).' 
            },
            { 
              label: 'BIMI Support', 
              key: 'v=BIMI1', 
              desc: 'Allows your verified brand logo to appear in email inboxes for authenticated messages.' 
            }
          ].map((item) => {
            let isActive = false;
            if (item.key === 'dnssec') {
              isActive = !!data.dns.audit?.dnssecEnabled;
            } else {
              const record = data.dns.records.find(r => r.data.toLowerCase().includes(item.key.toLowerCase()));
              isActive = !!record;
            }
            
            return (
              <div key={item.label} className="group relative p-4 rounded-2xl border border-surface-200 bg-white shadow-sm hover:border-blue-300 hover:shadow-md transition-all cursor-help">
                <div className="flex items-center gap-1.5 mb-2">
                  <span className="text-[10px] font-bold text-surface-400 uppercase tracking-widest leading-none">{item.label}</span>
                  <span className="text-[10px] opacity-40">?</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${isActive ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]' : 'bg-surface-300'}`} />
                  <span className={`text-xs font-black uppercase tracking-widest ${isActive ? 'text-emerald-600' : 'text-surface-400'}`}>
                    {isActive ? 'ACTIVE' : 'MISSING'}
                  </span>
                </div>

                {/* Tooltip */}
                <div className="absolute top-full left-0 mt-2 hidden group-hover:block w-52 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 font-normal border border-surface-700 animate-in fade-in duration-200 leading-relaxed">
                  {item.desc}
                </div>
              </div>
            );
          })}
        </div>

        {/* Email Spoofing Protection (Relocated for Consolidation) */}
        {data.emailSecurity && (
          <div className="mb-10 p-6 rounded-3xl bg-blue-50/50 border border-blue-100 shadow-inner">
            <div className="flex items-center gap-2 mb-6">
              <Mail className="h-4 w-4 text-blue-500" />
              <p className="text-[10px] font-black text-blue-600 uppercase tracking-widest">
                Identity & Sending Authority
              </p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="group relative p-5 rounded-2xl bg-white border border-surface-200 cursor-help shadow-sm hover:shadow-md transition-all">
                <div className="flex items-center justify-between mb-4">
                  <span className="text-xs font-bold text-surface-700 flex items-center gap-1 uppercase tracking-wider">
                    SPF Mechanism <span className="text-[10px] opacity-40">?</span>
                  </span>
                  <span className={`px-2 py-0.5 rounded-lg text-[10px] font-black uppercase tracking-widest ${
                    data.emailSecurity.spf.securityStatus === 'secure' ? 'bg-emerald-100 text-emerald-600' : 
                    data.emailSecurity.spf.securityStatus === 'warning' ? 'bg-amber-100 text-amber-600' : 
                    'bg-red-100 text-red-600'
                  }`}>
                    {data.emailSecurity.spf.securityStatus === 'unsafe' ? 'danger' : data.emailSecurity.spf.securityStatus}
                  </span>
                </div>
                <div className="bg-surface-50 p-3 rounded-xl border border-surface-100 mb-3">
                  <p className="text-xs text-surface-600 font-mono break-all leading-relaxed">{data.emailSecurity.spf.mechanism}</p>
                </div>
                <div className="text-[10px] text-surface-400 mb-4 font-bold flex items-center gap-1.5">
                   <div className={cn("w-1.5 h-1.5 rounded-full", data.emailSecurity.spf.lookupCount <= 10 ? "bg-emerald-500" : "bg-red-500")} />
                   DNS LOOKUPS: {data.emailSecurity.spf.lookupCount} / 10
                </div>
                <SolutionBlock solution={data.emailSecurity.spf.recommendation} title="SPF Action Required" />
                
                <div className="absolute left-0 bottom-full mb-2 hidden group-hover:block w-64 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 text-center font-normal border border-surface-700 animate-in fade-in duration-200">
                  Defines authorized sending IPs. If lookups exceed 10, receiving servers will fail the check, causing your emails to go to spam.
                </div>
              </div>

              <div className="group relative p-5 rounded-2xl bg-white border border-surface-200 cursor-help shadow-sm hover:shadow-md transition-all">
                <div className="flex items-center justify-between mb-4">
                  <span className="text-xs font-bold text-surface-700 flex items-center gap-1 uppercase tracking-wider">
                    DMARC Enforcement <span className="text-[10px] opacity-40">?</span>
                  </span>
                  <span className={`px-2 py-0.5 rounded-lg text-[10px] font-black uppercase tracking-widest ${
                    data.emailSecurity.dmarc.securityStatus === 'secure' ? 'bg-emerald-100 text-emerald-600' : 
                    data.emailSecurity.dmarc.securityStatus === 'warning' ? 'bg-amber-100 text-amber-600' : 
                    'bg-red-100 text-red-600'
                  }`}>
                    {data.emailSecurity.dmarc.securityStatus === 'unsafe' ? 'danger' : data.emailSecurity.dmarc.securityStatus}
                  </span>
                </div>
                <div className="bg-surface-50 p-3 rounded-xl border border-surface-100 mb-3">
                  <p className="text-xs text-surface-600 font-mono font-bold">POLICY: {data.emailSecurity.dmarc.policy}</p>
                </div>
                <p className="text-[10px] text-surface-400 mb-4 font-bold">
                  {data.emailSecurity.dmarc.policy === 'REJECT' 
                    ? '✓ Full Enforcement: spoofed emails are rejected.' 
                    : '⚠ Monitoring Only: domain can still be spoofed.'}
                </p>
                <SolutionBlock solution={data.emailSecurity.dmarc.recommendation} title="DMARC Action Required" />

                <div className="absolute left-0 bottom-full mb-2 hidden group-hover:block w-64 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 text-center font-normal border border-surface-700 animate-in fade-in duration-200">
                  DMARC uses SPF/DKIM to verify senders. A 'REJECT' policy is the gold standard for preventing brand impersonation.
                </div>
              </div>
            </div>
          </div>
        )}

        {data.dns.audit?.recommendations && data.dns.audit.recommendations.length > 0 && (
          <div className="mb-10 space-y-4">
            <p className="text-[10px] font-black text-blue-600 uppercase tracking-widest px-1">Infrastructure Hardening:</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {data.dns.audit.recommendations.map((rec, i) => (
                <SolutionBlock key={i} solution={rec} title="DNS Technical Fix" />
              ))}
            </div>
          </div>
        )}

        <div className="space-y-4">
          <p className="text-[10px] font-bold text-surface-400 uppercase tracking-widest px-1">
            Detailed Record Table
          </p>
          <div className="overflow-x-auto rounded-2xl border border-surface-200 bg-white shadow-sm">
            <table className="w-full text-[11px]">
              <thead>
                <tr className="bg-surface-50/50 text-surface-500 border-b border-surface-200">
                  <th className="text-left px-6 py-3 font-bold uppercase tracking-wider">Type</th>
                  <th className="text-left px-6 py-3 font-bold uppercase tracking-wider">Data / Value</th>
                  <th className="text-right px-6 py-3 font-bold uppercase tracking-wider">TTL</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-100">
                {data.dns.records.map((record, i) => (
                  <tr key={i} className="group transition-colors hover:bg-blue-50/30">
                    <td className="px-6 py-3 align-top">
                      <div className="relative flex items-center gap-1 cursor-help group/type">
                        <span className="font-black text-blue-600 px-2 py-0.5 rounded-lg bg-blue-50 border border-blue-100 text-[10px]">
                          {record.type}
                        </span>
                        
                        {/* Recursive Tooltip */}
                        <div className="absolute left-full ml-2 top-0 hidden group-hover/type:block w-48 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 font-normal border border-surface-700 animate-in fade-in slide-in-from-left-1 duration-200">
                          {record.type === 'A' && "Points to the IPv4 address. Tells the internet where your website is hosted."}
                          {record.type === 'AAAA' && "Points to the IPv6 address (the modern standard for IP addresses)."}
                          {record.type === 'MX' && "Mail Exchange: Specified the servers that receive email for your domain."}
                          {record.type === 'TXT' && "Text Record: Used for site verification and security policies like SPF/DMARC."}
                          {record.type === 'CNAME' && "Canonical Name: Alias of one name to another (common for subdomains)."}
                          {record.type === 'NS' && "Nameserver: Authoritative server for your domain's records."}
                          {record.type === 'CAA' && "Certificate Authority Authorization: Specifies which CAs can issue SSL certs."}
                          {(!['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'CAA'].includes(record.type)) && "A standard DNS record for domain configuration."}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-3 font-mono text-surface-600 break-all leading-relaxed">
                      {record.data}
                    </td>
                    <td className="px-6 py-3 text-right text-surface-400 font-bold whitespace-nowrap">
                      {record.ttl}s
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </CollapsibleSection>

      {/* Tech Stack */}
      <CollapsibleSection
        title="Technology Audit & Stack"
        subtitle="Detection and health analysis of the underlying framework, libraries, and utilities powering the asset."
        icon={<Cpu className="h-5 w-5 text-indigo-500" />}
        defaultExpanded={(data.techStackHealth?.modernityScore ?? 0) <= 70}
        badge={
          data.techStackHealth && (
            <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-widest ${
              data.techStackHealth.modernityScore > 70 ? 'bg-emerald-100 text-emerald-600' : 'bg-amber-100 text-amber-600'
            }`}>
              {data.techStackHealth.modernityScore > 70 ? 'Modern Stack' : 'Legacy Detected'}
            </span>
          )
        }
        className="border-l-4 border-l-indigo-500 bg-white"
      >
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 mb-8">
          {data.techStackHealth && (
            <div className="flex items-center gap-6 p-4 rounded-2xl bg-white border border-surface-200 shadow-sm">
              <div className="group relative flex flex-col cursor-help">
                <span className="text-[10px] font-bold text-surface-400 uppercase tracking-widest mb-1">Modernity Score</span>
                <div className="flex items-center gap-2">
                  <span className={`text-2xl font-black ${data.techStackHealth.modernityScore > 80 ? 'text-indigo-600' : 'text-yellow-600'}`}>
                    {data.techStackHealth.modernityScore}
                  </span>
                  <span className="text-xs text-surface-400 font-bold">/ 100</span>
                </div>
                
                {/* Tooltip */}
                <div className="absolute bottom-full left-0 mb-2 hidden group-hover:block w-56 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 text-center font-normal border border-surface-700 animate-in fade-in duration-200">
                  Overall evaluation of how up-to-date your technology stack is. High scores indicate modern, standardized frameworks.
                </div>
              </div>
              <div className="h-8 w-px bg-surface-100 hidden sm:block" />
              <div className="flex-1">
                {data.techStackHealth?.recommendation && (
                  <SolutionBlock solution={data.techStackHealth.recommendation} title="Modernization Strategy" />
                )}
              </div>
            </div>
          )}
        </div>

        {data.techStackHealth?.technicalDebt && data.techStackHealth.technicalDebt.length > 0 && (
          <div className="group relative mb-8 p-4 rounded-2xl bg-amber-50 border border-amber-100 cursor-help shadow-sm">
            <p className="text-[10px] font-black text-amber-800 uppercase tracking-widest mb-3 flex items-center gap-2">
              <ShieldAlert className="h-3 w-3" /> Technical Debt Alerts
            </p>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2">
              {data.techStackHealth.technicalDebt.map((debt, i) => (
                <li key={i} className="text-xs text-amber-700 font-medium flex items-start gap-2 leading-relaxed">
                  <span className="mt-1.5 flex h-1 w-1 shrink-0 rounded-full bg-amber-500" />
                  {debt}
                </li>
              ))}
            </ul>

            {/* Tooltip */}
            <div className="absolute bottom-full left-0 mb-2 hidden group-hover:block w-64 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 font-normal border border-surface-700 animate-in fade-in duration-200">
              Detects redundant or conflicting libraries that increase bundle size and maintenance complexity.
            </div>
          </div>
        )}

        {data.techStack.length === 0 ? (
          <div className="py-12 text-center border-2 border-dashed border-surface-200 rounded-2xl">
            <p className="text-sm text-surface-400 italic">No technologies detected from main entry point.</p>
          </div>
        ) : (
          <div className="space-y-8">
            {Object.entries(
              data.techStack.reduce(
                (acc, tech) => {
                  const layer = tech.layer || "Other Services";
                  if (!acc[layer]) acc[layer] = [];
                  acc[layer].push(tech);
                  return acc;
                },
                {} as Record<string, typeof data.techStack>,
              ),
            ).map(([layer, techs]) => (
              <div key={layer}>
                <h4 className="text-[10px] font-black text-surface-400 uppercase tracking-widest mb-4 border-b border-surface-100 pb-2 px-1">
                  {layer}
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                  {techs.map((tech) => (
                    <div key={tech.name} className="flex flex-col gap-2">
                      <div
                        className={`group relative flex items-center justify-between px-4 py-3 rounded-2xl border text-xs font-bold shadow-sm transition-all hover:shadow-md hover:-translate-y-0.5 cursor-help ${
                          tech.isOutdated || tech.isLegacy
                            ? "border-red-100 bg-white text-red-700"
                            : "border-surface-200 bg-white text-surface-700"
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <div className={cn(
                            "h-8 w-8 rounded-lg flex items-center justify-center text-[10px] font-black",
                            tech.isOutdated || tech.isLegacy ? "bg-red-50 text-red-600" : "bg-surface-50 text-surface-500"
                          )}>
                            {tech.name.substring(0, 2).toUpperCase()}
                          </div>
                          <div className="flex flex-col">
                            <span className="truncate max-w-[120px]">{tech.name}</span>
                            {tech.version && <span className="text-[9px] opacity-40 font-mono tracking-tighter">v{tech.version}</span>}
                          </div>
                        </div>
                        
                        <div className="flex items-center gap-2">
                          {tech.impact && (
                            <span 
                              className={`px-1.5 py-0.5 rounded-[6px] text-[8px] font-black uppercase tracking-tighter shrink-0 ${
                                tech.impact === 'high' ? 'bg-red-100 text-red-600' : 
                                tech.impact === 'medium' ? 'bg-amber-100 text-amber-600' : 
                                'bg-emerald-100 text-emerald-600'
                              }`}
                            >
                              {tech.impact}
                            </span>
                          )}
                          
                          {(tech.isOutdated || tech.isLegacy) && (
                            <div className="relative flex h-2 w-2">
                              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                              <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                            </div>
                          )}
                        </div>

                        {/* Tooltip */}
                        <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block w-52 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in duration-200 border border-surface-700 font-normal">
                          <p className="font-black mb-1 border-b border-surface-700 pb-1 text-center uppercase tracking-widest text-[9px]">
                            {tech.name}
                          </p>
                          <ul className="space-y-1.5 pt-1.5 leading-relaxed">
                            {tech.isOutdated ? (
                              <li className="text-red-400 font-bold">⚠️ Outdated version detected.</li>
                            ) : tech.isLegacy ? (
                              <li className="text-amber-400 font-bold">📜 Legacy technology detected.</li>
                            ) : (
                              <li className="text-emerald-400 font-bold">✓ Modern Industry Standard</li>
                            )}
                            <li className="text-surface-300">
                              <span className="font-bold">Perf Impact:</span> {
                                tech.impact === 'high' ? "Significant overhead." :
                                tech.impact === 'medium' ? "Moderate footprint." :
                                "Lightweight & efficient."
                              }
                            </li>
                          </ul>
                        </div>
                      </div>
                      {tech.recommendation && (tech.isOutdated || tech.isLegacy) && (
                        <div className="px-1">
                          <SolutionBlock solution={tech.recommendation} title="Fix" />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </CollapsibleSection>

      {/* Server Intelligence */}
      {data.server && (
        <CollapsibleSection
          title="Server Intelligence & Infrastructure"
          subtitle="Deep-dive into the physical host, network reputation, and localized providing environment."
          icon={<Server className="h-5 w-5 text-purple-500" />}
          defaultExpanded={!!data.server.blacklisted}
          badge={
            <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-widest ${
              data.server.blacklisted ? 'bg-red-100 text-red-600 animate-pulse' : 'bg-emerald-100 text-emerald-600'
            }`}>
              {data.server.blacklisted ? 'Risk Detected' : 'Clean Reputation'}
            </span>
          }
          className="border-l-4 border-l-purple-500 bg-white"
        >
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-1 space-y-6">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-1 gap-4">
                <div className="group relative cursor-help p-4 rounded-2xl bg-white border border-surface-200 shadow-sm hover:shadow-md transition-all">
                  <div className="flex items-center justify-between mb-1">
                    <p className="text-xs text-surface-500">Edge Discovery Location</p>
                    <HelpCircle className="h-3 w-3 text-surface-300" />
                  </div>
                  <p className="text-sm font-medium text-surface-900">
                    {data.server.location?.city ?? "Unknown"}, {data.server.location?.country ?? "Unknown"} {data.server.location?.dataCenter ? `[${data.server.location.dataCenter}]` : ""}
                  </p>
                  <div className="absolute top-full left-0 mt-2 hidden group-hover:block w-64 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 font-normal border border-surface-700 animate-in fade-in duration-200 leading-relaxed">
                    <p className="font-bold mb-1">Why this location?</p>
                    Since this website uses a CDN ({data.server.location?.provider || 'Cloudflare'}), you are seeing the location of the nearest "Edge" node that served the request, ensuring high-speed delivery.
                  </div>
                </div>

                <div className="group relative cursor-help p-4 rounded-2xl bg-white border border-surface-200 shadow-sm hover:shadow-md transition-all">
                  <SslField label="IP Address" value={data.server.ip} />
                  <div className="absolute top-full left-0 mt-2 hidden group-hover:block w-48 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 font-normal border border-surface-700 animate-in fade-in duration-200">
                    The unique numerical label assigned to the server hosting your website files.
                  </div>
                </div>

                <div className="group relative cursor-help p-4 rounded-2xl bg-white border border-surface-200 shadow-sm hover:shadow-md transition-all">
                  <SslField
                    label="Network Latency"
                    value={data.server.location?.latencyMs ? `${data.server.location.latencyMs}ms` : "N/A"}
                  />
                  <div className="absolute top-full left-0 mt-2 hidden group-hover:block w-48 bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 font-normal border border-surface-700 animate-in fade-in duration-200">
                    The round-trip time (RTT) from our audit engine to the server. Lower is better.
                  </div>
                </div>

                <div className="group relative cursor-help p-4 rounded-2xl bg-white border border-surface-200 shadow-sm hover:shadow-md transition-all">
                  <SslField label="Provider / ASN" value={data.server.location?.provider || `${data.server.location?.isp ?? "Unknown"} (AS${data.server.location?.as ?? "?"})`} />
                  <div className="absolute top-full left-0 mt-2 hidden group-hover:block w-full max-w-xs bg-surface-900 text-white text-[10px] px-3 py-2 rounded-xl shadow-2xl z-50 font-normal border border-surface-700 animate-in fade-in duration-200">
                    Identified Infrastructure Provider and the Autonomous System Number.
                  </div>
                </div>
              </div>
              
              {data.server.blacklisted && (
                <div className="p-4 rounded-2xl bg-red-50 border border-red-100 flex items-start gap-4">
                  <ShieldAlert className="h-5 w-5 text-red-500 mt-1 shrink-0" />
                  <div>
                    <h4 className="text-sm font-bold text-red-900 uppercase tracking-tight mb-1">Reputation Alert: IP Blacklisted</h4>
                    <p className="text-xs text-red-700 leading-relaxed font-medium">
                      Your server's IP address has been flagged as a source of spam or malicious activity. This can severely impact email delivery and SEO ranking.
                    </p>
                  </div>
                </div>
              )}
            </div>

            <div className="lg:col-span-2">
              <NetworkTopology
                provider={data.server?.location?.provider || "Unknown Provider"}
                dataCenter={data.server?.location?.dataCenter}
                city={data.server?.location?.city}
                latency={data.server?.location?.latencyMs}
                domain={data.domain}
              />
            </div>
          </div>
        </CollapsibleSection>
      )}

      {/* SSL Certificate */}
      <CollapsibleSection
        title="SSL Certificate & Encryption Audit"
        subtitle="Verification of the cryptographic identity and transport security layer (TLS) health."
        icon={<ShieldCheck className="h-5 w-5 text-emerald-500" />}
        defaultExpanded={!(displaySSL && displaySSL.daysUntilExpiry !== null && displaySSL.daysUntilExpiry > 7)}
        badge={
          displaySSL && (
            <div className="flex items-center gap-2">
              {displaySSL.deepScanStatus === 'scanning' && (
                <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-widest bg-blue-100 text-blue-600">
                  <div className="h-1 w-1 rounded-full bg-blue-600 animate-ping" />
                  Deep Audit {deepScanProgress}%
                </span>
              )}
              {displaySSL.deepScanStatus === 'ready' && (
                <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-widest bg-emerald-100 text-emerald-600">
                  <Check className="h-3 w-3" />
                  Verified
                </span>
              )}
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-widest ${
                displaySSL.daysUntilExpiry === null
                  ? 'bg-surface-100 text-surface-500'
                  : displaySSL.daysUntilExpiry > 7
                    ? 'bg-emerald-100 text-emerald-600'
                    : 'bg-red-100 text-red-600 animate-pulse'
              }`}>
                {displaySSL.daysUntilExpiry === null ? 'Checking...' : displaySSL.daysUntilExpiry > 7 ? 'Valid' : 'Action Required'}
              </span>
            </div>
          )
        }
        className="border-l-4 border-l-emerald-500 bg-emerald-50/5"
      >
        {!displaySSL ? (
          <div className="py-12 text-center border-2 border-dashed border-surface-200 rounded-2xl">
            <p className="text-sm text-surface-400 italic">No SSL certificate information detected for this domain.</p>
          </div>
        ) : (
          <div className="space-y-8">
            {/* Deep Scan Progress Bar */}
            {displaySSL.deepScanStatus === "scanning" && (
              <div className="px-1">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-bold text-blue-600 uppercase tracking-widest">Live Deep Audit</span>
                  <span className="text-[10px] font-bold text-blue-600 tabular-nums">{deepScanProgress}%</span>
                </div>
                <div className="h-1.5 bg-surface-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-blue-500 to-emerald-500 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${deepScanProgress}%` }}
                  />
                </div>
                <p className="text-[10px] text-surface-400 mt-1.5">
                  {deepScanStalled
                    ? "SSL Labs is taking longer than usual. Results will update automatically when ready."
                    : deepScanProgress < 30 ? "Initiating SSL Labs handshake..."
                    : deepScanProgress < 60 ? "Analyzing TLS configuration & cipher suites..."
                    : deepScanProgress < 85 ? "Checking for vulnerabilities (Heartbleed, POODLE, etc.)..."
                    : "Finalizing security grade..."}
                </p>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="p-4 rounded-2xl bg-white border border-surface-200 shadow-sm">
                <SslField
                  label="Subject (Owner)"
                  value={displaySSL.subject === "Unknown" && displaySSL.deepScanStatus === "scanning" ? "Gathering Info..." : displaySSL.subject}
                />
              </div>
              <div className="p-4 rounded-2xl bg-white border border-surface-200 shadow-sm">
                <SslField
                  label="Issuer (CA)"
                  value={displaySSL.issuer === "Unknown" && displaySSL.deepScanStatus === "scanning" ? "Verifying Handshake..." : displaySSL.issuer}
                />
              </div>
              <div className="p-4 rounded-2xl bg-white border border-surface-200 shadow-sm">
                <SslField
                  label="Validity Window"
                  value={
                    !displaySSL.validFrom || displaySSL.validFrom === "Unknown" || isNaN(new Date(displaySSL.validFrom).getTime())
                      ? "Checking Expiry..."
                      : `${new Date(displaySSL.validFrom).toLocaleDateString()} → ${new Date(displaySSL.validTo).toLocaleDateString()}`
                  }
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="p-6 rounded-2xl bg-white border border-surface-200 shadow-sm">
                <span className="text-[10px] font-bold text-surface-400 uppercase tracking-widest block mb-4">Days Until Expiry</span>
                <div className="flex items-baseline gap-2">
                  <span className={`text-4xl font-black ${
                    displaySSL.daysUntilExpiry === null ? 'text-surface-200 animate-pulse' :
                    displaySSL.daysUntilExpiry < 30 ? 'text-red-600' :
                    displaySSL.daysUntilExpiry < 90 ? 'text-amber-600' :
                    'text-emerald-600'
                  }`}>
                    {displaySSL.daysUntilExpiry === null ? "..." : displaySSL.daysUntilExpiry}
                  </span>
                  <span className="text-sm font-bold text-surface-400 uppercase tracking-tight">Days</span>
                </div>
                <div className="mt-8">
                  {reminderSet ? (
                    <div className="flex items-center gap-2 text-emerald-600 bg-emerald-50 px-3 py-2.5 rounded-xl border border-emerald-100">
                      <Bell className="h-4 w-4" />
                      <span className="text-[10px] font-black uppercase tracking-widest">Monitoring Active</span>
                    </div>
                  ) : (
                    <button
                      onClick={() => {
                        if (!isAuthenticated) {
                          alert("🔒 AUTH REQUIRED: Please log in first.");
                          return;
                        }
                        if (data.domain && displaySSL?.validTo) {
                          reminderMutation.mutate({
                            domain: data.domain,
                            expiryDate: displaySSL.validTo,
                          });
                        }
                      }}
                      disabled={reminderMutation.isPending}
                      className="w-full py-2.5 px-4 rounded-xl border border-surface-200 text-[11px] font-bold text-surface-600 hover:bg-surface-50 transition-all flex items-center justify-center gap-2 group"
                    >
                      {reminderMutation.isPending ? <Spinner size="sm" /> : <Bell className="w-3.5 h-3.5 text-emerald-500 group-hover:scale-110 transition-transform" />}
                      ENABLE EMAIL ALERT
                    </button>
                  )}
                </div>
              </div>

              <div className="p-6 rounded-2xl bg-white border border-surface-200 shadow-sm flex flex-col items-center justify-center text-center relative overflow-hidden group">
                <span className="text-[10px] font-bold text-surface-400 uppercase tracking-widest absolute top-6">Security Grade</span>
                {displaySSL.grade ? (
                  <div className="flex flex-col items-center">
                    <span className={`text-7xl font-black mb-2 transition-all duration-700 ${
                      displaySSL.grade.startsWith('A') ? 'text-emerald-500' :
                      displaySSL.grade.startsWith('B') ? 'text-blue-500' :
                      displaySSL.grade.startsWith('C') ? 'text-amber-500' :
                      'text-red-500'
                    }`}>
                      {displaySSL.grade}
                    </span>
                    <span className="text-[10px] font-bold text-surface-400 uppercase tracking-widest">
                      {displaySSL.deepScanStatus === "ready" ? "SSL Labs Verified" : "Preliminary Grade"}
                    </span>
                  </div>
                ) : (
                  <div className="flex flex-col items-center gap-3">
                    <div className="w-16 h-16 rounded-2xl bg-surface-50 flex items-center justify-center animate-pulse">
                      <div className="w-8 h-8 rounded-lg bg-surface-200" />
                    </div>
                    <span className="text-[10px] font-bold text-emerald-500 uppercase tracking-widest animate-pulse">Probing...</span>
                  </div>
                )}
              </div>

              <div className="p-6 rounded-2xl bg-white border border-surface-200 shadow-sm">
                <span className="text-[10px] font-bold text-surface-400 uppercase tracking-widest block mb-4">TLS Protocol</span>
                {displaySSL.protocol ? (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-lg font-black text-surface-900">{displaySSL.protocol}</span>
                      <div className="px-2 py-0.5 rounded-md bg-emerald-50 text-emerald-600 text-[10px] font-bold">ACTIVE</div>
                    </div>
                    <div className="pt-4 border-t border-surface-100 flex items-center justify-between">
                      <span className="text-[10px] font-bold text-surface-400 uppercase tracking-widest">Cipher strength</span>
                      <span className="text-xs font-bold text-surface-900">{displaySSL.keySize ? `${displaySSL.keySize}-bit ${displaySSL.keyAlgorithm}` : '---'}</span>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4 animate-pulse">
                    <div className="h-6 w-24 bg-surface-100 rounded-md" />
                    <div className="pt-4 border-t border-surface-100 h-4 w-full bg-surface-50 rounded-sm" />
                  </div>
                )}
              </div>
            </div>

            {displaySSL.recommendation && (
              <div className="pt-2 px-1">
                <SolutionBlock solution={displaySSL.recommendation} title="Security Hardening Fix" />
              </div>
            )}

            <div className="pt-8 border-t border-surface-100">
              <p className="text-[10px] font-black text-surface-400 uppercase tracking-widest mb-4 px-1">
                Security Compliance & Protocols
              </p>
              <div className="flex flex-wrap gap-2">
                <SecurityBadge
                  label="HSTS"
                  enabled={displaySSL.hstsEnabled}
                  description="Strict Transport Security: Forces browsers to only connect via HTTPS, preventing downgrade attacks."
                />
                <SecurityBadge
                  label="Vulnerability Free"
                  enabled={displaySSL.isVulnerable === false}
                  description="Verifies protection against known SSL/TLS flaws like Heartbleed and POODLE."
                />
                <SecurityBadge
                  label="Forward Secrecy"
                  enabled={displaySSL.forwardSecrecy}
                  description="Ensures past encryption keys remain secure even if the server's private key is stolen."
                />
                <SecurityBadge
                  label="OCSP Stapling"
                  enabled={displaySSL.ocspStapling}
                  description="Improves user privacy and site performance by providing certificate status locally."
                />
                <SecurityBadge
                  label="ALPN (HTTP/2-3)"
                  enabled={displaySSL.alpnSupported}
                  description="Supports modern protocols for much faster page loading and better multiplexing."
                />
                <SecurityBadge
                  label="TLS 1.3"
                  enabled={displaySSL.tls13Enabled}
                  description="The latest and most secure encryption standard, offering faster and safer handshakes."
                />
                <SecurityBadge
                  label="TLS 1.2"
                  enabled={displaySSL.tls12Enabled}
                  description="The standard secure protocol version for broad browser compatibility."
                />
                <SecurityBadge
                  label="CT Compliant"
                  enabled={displaySSL.ctCompliant}
                  description="Certificate Transparency: Proof that the certificate is publicly logged and legitimate."
                />
                <SecurityBadge
                  label="CAA Record"
                  enabled={displaySSL.caaRecordPresent}
                  description="DNS security layer that limits which CAs are allowed to issue certificates for you."
                />
              </div>
            </div>
          </div>
        )}
      </CollapsibleSection>
    </div>
  );
}

export function SolutionBlock({ solution, title = "How to Fix" }: { solution?: string; title?: string }) {
  if (!solution) return null;
  const isWarning = title.toLowerCase().includes("action") || title.toLowerCase().includes("fix") || title.toLowerCase().includes("required");
  
  return (
    <div className={cn(
      "mt-2 p-3 border rounded-lg animate-fade-in group/solution shadow-sm",
      isWarning 
        ? "bg-red-50/80 border-red-200 shadow-red-100/20" 
        : "bg-brand-50/80 border-brand-100 shadow-brand-100/20"
    )}>
      <div className="flex items-start gap-2">
        <div className={cn(
          "mt-0.5 p-1 rounded-md shrink-0 transition-transform group-hover/solution:scale-110",
          isWarning ? "bg-red-600 text-white" : "bg-brand-600 text-white"
        )}>
          {isWarning ? <AlertCircle className="h-3 w-3" /> : <Check className="h-3 w-3" />}
        </div>
        <div>
          <p className={cn(
            "text-[10px] font-black uppercase tracking-widest mb-1",
            isWarning ? "text-red-600" : "text-brand-600"
          )}>{title}</p>
          <p className={cn(
            "text-[11px] leading-relaxed font-bold",
            isWarning ? "text-red-950" : "text-brand-950"
          )}>
            {solution}
          </p>
        </div>
      </div>
    </div>
  );
}

export function SecurityBadge({
  label,
  enabled,
  description,
}: {
  label: string;
  enabled: boolean | null;
  description: string;
}) {
  const statusClass =
    enabled === null
      ? "bg-surface-100 text-surface-500 border-surface-200"
      : enabled
        ? "bg-green-50 text-green-700 border-green-200"
        : "bg-red-50 text-red-700 border-red-200";

  return (
    <div
      className={`group relative flex items-center px-3 py-1.5 rounded-full border text-[10px] font-medium ${statusClass} cursor-help transition-all hover:scale-105 shadow-sm`}
    >
      <span className="flex h-1.5 w-1.5 rounded-full bg-current mr-1.5" />
      {label}
      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block w-48 bg-surface-900 text-white text-[10px] px-2 py-1.5 rounded-lg shadow-xl z-50 text-center animate-fade-in border border-surface-700">
        <p className="font-semibold mb-1 border-b border-surface-700 pb-1">{label}</p>
        <p className="leading-relaxed">{description}</p>
        {enabled === null && (
          <p className="mt-1 text-surface-400 italic">(Checking status...)</p>
        )}
      </div>
    </div>
  );
}

export function SslField({
  label,
  value,
  status,
}: {
  label: string;
  value: string | number | null;
  status?: "success" | "warning" | "danger";
}) {
  const statusColor = status
    ? {
        success: "text-green-700",
        warning: "text-yellow-700",
        danger: "text-red-700",
      }[status]
    : "text-surface-900";

  return (
    <div>
      <p className="text-xs text-surface-500 mb-1">{label}</p>
      <p className={`text-sm font-medium ${statusColor}`}>{value ?? "N/A"}</p>
    </div>
  );
}

export function NetworkTopology({ 
  provider, 
  dataCenter, 
  city, 
  latency,
  domain 
}: { 
  provider: string; 
  dataCenter?: string; 
  city?: string; 
  latency?: number;
  domain: string;
}) {
  const isCdn = provider.toLowerCase().includes("cloudflare") || 
                provider.toLowerCase().includes("fastly") || 
                provider.toLowerCase().includes("vercel") ||
                provider.toLowerCase().includes("amazon");

  return (
    <div className="h-full min-h-[180px] rounded-3xl bg-white border border-surface-200 p-6 relative overflow-hidden flex flex-col justify-between shadow-sm group/topo">
      <div className="absolute inset-0 opacity-[0.4] pointer-events-none" 
           style={{ backgroundImage: "radial-gradient(circle at 2px 2px, #e2e8f0 1px, transparent 0)", backgroundSize: "24px 24px" }} />
      
      <div className="flex items-center justify-between relative z-10 mb-4">
        <div className="flex items-center gap-2">
          <Zap className="h-3.5 w-3.5 text-brand-600" />
          <span className="text-[10px] font-black text-surface-400 uppercase tracking-widest">Connection Route Integrity</span>
        </div>
        {latency && (
          <div className="px-2 py-0.5 rounded-md bg-brand-50 border border-brand-100 text-[10px] font-mono text-brand-700 font-bold">
            {latency}ms RTT
          </div>
        )}
      </div>

      <div className="flex items-center justify-between relative z-10 px-4">
        {/* Node: Client */}
        <div className="flex flex-col items-center gap-2">
          <div className="h-10 w-10 rounded-2xl bg-surface-50 border border-surface-200 flex items-center justify-center text-surface-600 transition-all group-hover/topo:scale-110 shadow-sm duration-500">
            <Monitor className="h-5 w-5" />
          </div>
          <span className="text-[10px] font-bold text-surface-400 uppercase tracking-tighter">Local System</span>
        </div>

        {/* Path 1 */}
        <div className="flex-1 px-4 relative flex flex-col items-center">
          <div className="h-[2px] w-full bg-gradient-to-r from-brand-600/0 via-brand-600/50 to-brand-600/0 relative">
            <div className="absolute top-1/2 left-0 w-2 h-2 rounded-full bg-brand-600 -translate-y-1/2 shadow-[0_0_8px_rgba(37,99,235,0.4)]" />
          </div>
          <span className="text-[9px] font-black text-brand-600/60 uppercase tracking-widest mt-2 px-2 bg-white relative z-10">Encrypted</span>
        </div>

        {/* Node: Edge/Transit */}
        <div className="flex flex-col items-center gap-2">
          <div className={cn(
            "h-12 w-12 rounded-2xl flex items-center justify-center transition-all duration-700 shadow-md",
            isCdn ? "bg-brand-600 text-white" : "bg-surface-100 text-surface-500 border border-surface-200"
          )}>
            <Server className="h-6 w-6" />
          </div>
          <div className="flex flex-col items-center">
            <span className={cn(
              "text-[9px] font-black uppercase tracking-tighter",
              isCdn ? "text-brand-600" : "text-surface-500"
            )}>
              {isCdn ? "Edge Node" : "Relay Hop"}
            </span>
            <span className="text-[10px] font-black text-surface-900 uppercase">
              {dataCenter || "Primary"}
            </span>
          </div>
        </div>

        {/* Path 2 */}
        <div className="flex-1 px-4 relative flex flex-col items-center">
          <div className="h-[2px] w-full border-t-2 border-dashed border-surface-200 relative" />
          <span className="text-[9px] font-black text-surface-300 uppercase tracking-widest mt-2">{isCdn ? "Secure Tunnel" : "Network Hop"}</span>
        </div>

        {/* Node: Destination */}
        <div className="flex flex-col items-center gap-2">
          <div className="h-10 w-10 rounded-2xl bg-white border border-brand-200 flex items-center justify-center text-brand-600 shadow-sm transition-all group-hover/topo:rotate-6">
            <Globe className="h-5 w-5" />
          </div>
          <span className="text-[10px] font-bold text-brand-600 uppercase tracking-tighter truncate max-w-[80px]">
            {domain}
          </span>
        </div>
      </div>

      <div className="mt-6 flex items-center gap-2 px-3 py-2 rounded-xl bg-surface-50 border border-surface-100">
        <div className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.3)]" />
        <p className="text-[11px] font-medium text-surface-600">
          Request optimized via <span className="text-brand-600 font-bold">{provider}</span> in <span className="text-surface-900 font-bold">{city || "Global Network"}</span>.
        </p>
      </div>
    </div>
  );
}
