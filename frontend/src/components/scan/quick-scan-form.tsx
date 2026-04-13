"use client";

import { Globe, Search, AlertCircle } from "lucide-react";
import { trpc } from "@/lib/trpc";
import { Spinner } from "@/components/ui/spinner";
import React, { useState, useEffect, type FormEvent } from "react";
import { ScanResults } from "./scan-results";

interface QuickScanFormProps {
  onScanComplete?: () => void;
  onScanStateChange?: (hasResults: boolean) => void;
  triggerUrl?: string | null;
}

export function QuickScanForm({ onScanComplete, onScanStateChange, triggerUrl }: QuickScanFormProps) {
  const [url, setUrl] = useState("");
 
  useEffect(() => {
    if (triggerUrl) {
      setUrl(triggerUrl);
      onScanStateChange?.(true);
      scanMutation.mutate({ url: triggerUrl, force: true });
    }
  }, [triggerUrl]);
 
  const scanMutation = trpc.scan.quick.useMutation({
    onSuccess: () => {
      onScanComplete?.();
    },
  });
 
  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!url.trim()) return;
    onScanStateChange?.(true);
    scanMutation.mutate({ url: url.trim(), force: true });
  }

  return (
    <div className="space-y-6">
      <form onSubmit={handleSubmit} className="flex gap-3">
        <div className="relative flex-1">
          <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-surface-400" />
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter a website URL (e.g., example.com)"
            className="input pl-11"
            disabled={scanMutation.isPending}
          />
        </div>
        <button
          type="submit"
          disabled={!url.trim() || scanMutation.isPending}
          className="btn-primary gap-2"
        >
          {scanMutation.isPending ? (
            <Spinner size="sm" className="text-white" />
          ) : (
            <Search className="h-4 w-4" />
          )}
          {scanMutation.isPending ? "Scanning..." : "SCAN WEBSITE"}
        </button>
      </form>

      {scanMutation.error && (
        <div className="flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 p-4">
          <AlertCircle className="h-5 w-5 text-red-500 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-red-800">Scan failed</p>
            <p className="text-sm text-red-600 mt-1">
              {scanMutation.error.message}
            </p>
          </div>
        </div>
      )}

      {scanMutation.data && (
        <ScanResults
          data={scanMutation.data}
          isRefreshing={scanMutation.isPending}
          onRefresh={() =>
            scanMutation.mutate({ url: scanMutation.data!.url, force: true })
          }
          showSaveBrandButton={false}
        />
      )}
    </div>
  );
}
