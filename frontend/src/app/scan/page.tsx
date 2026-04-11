"use client";

import { Navbar } from "@/components/dashboard/navbar";
import { QuickScanForm } from "@/components/scan/quick-scan-form";

export default function ScanPage() {
  return (
    <div className="min-h-screen bg-surface-50">
      <Navbar />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-surface-900">
            Website Scanner
          </h1>
          <p className="text-sm text-surface-500 mt-1">
            Analyze any website&apos;s technology stack, DNS configuration, and SSL
            certificate status.
          </p>
        </div>
        <div className="card p-6">
          <QuickScanForm />
        </div>
      </main>
    </div>
  );
}
