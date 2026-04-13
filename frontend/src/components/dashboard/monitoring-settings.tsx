"use client";

import { useState, useEffect } from "react";
import { trpc } from "@/lib/trpc";
import { 
  Bell, 
  Mail, 
  Plus, 
  X, 
  CheckCircle2, 
  AlertCircle,
  Calendar,
  Settings2,
  Trash2
} from "lucide-react";
import { Spinner } from "@/components/ui/spinner";

interface MonitoringSettingsProps {
  domain: string;
  expiryDate: string;
}

const DEFAULT_THRESHOLDS = [30, 15, 7, 3, 1];

export function MonitoringSettings({ domain, expiryDate }: MonitoringSettingsProps) {
  const [emails, setEmails] = useState<string[]>([]);
  const [newEmail, setNewEmail] = useState("");
  const [thresholds, setThresholds] = useState<number[]>([30, 7, 1]);
  const [isEnabled, setIsEnabled] = useState(true);
  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "success" | "error">("idle");

  const utils = trpc.useUtils();
  
  // Fetch existing reminder settings
  const { data: reminders, isLoading } = trpc.reminder.list.useQuery();
  const existingReminder = reminders?.find((r: any) => r.domain === domain);

  useEffect(() => {
    if (existingReminder) {
      setEmails(existingReminder.notifyEmails || []);
      setThresholds(existingReminder.thresholdDays || [30, 7, 1]);
      setIsEnabled(existingReminder.isEnabled ?? true);
    }
  }, [existingReminder]);

  const setReminderMutation = trpc.reminder.setSslReminder.useMutation({
    onSuccess: () => {
      setSaveStatus("success");
      utils.reminder.list.invalidate();
      setTimeout(() => setSaveStatus("idle"), 3000);
    },
    onError: () => {
      setSaveStatus("error");
      setTimeout(() => setSaveStatus("idle"), 3000);
    }
  });

  const handleSave = () => {
    setSaveStatus("saving");
    setReminderMutation.mutate({
      domain,
      expiryDate,
      notifyEmails: emails,
      thresholdDays: thresholds,
      isEnabled
    });
  };

  const addEmail = () => {
    if (!newEmail.trim()) return;
    if (!newEmail.includes("@")) return;
    if (emails.includes(newEmail.trim())) return;
    setEmails([...emails, newEmail.trim()]);
    setNewEmail("");
  };

  const removeEmail = (email: string) => {
    setEmails(emails.filter(e => e !== email));
  };

  const toggleThreshold = (days: number) => {
    if (thresholds.includes(days)) {
      setThresholds(thresholds.filter(t => t !== days));
    } else {
      setThresholds([...thresholds, days].sort((a, b) => b - a));
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-12">
        <Spinner size="lg" />
      </div>
    );
  }

  return (
    <div className="card border-surface-200 bg-white shadow-sm overflow-hidden animate-in fade-in slide-in-from-bottom-2 duration-500">
      <div className="p-6 border-b border-surface-100 bg-surface-50/30 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-brand-600 flex items-center justify-center text-white shadow-lg shadow-brand-100">
            <Bell className="h-5 w-5" />
          </div>
          <div>
            <h3 className="text-base font-black text-surface-900 uppercase tracking-tight">Active Monitoring</h3>
            <p className="text-[10px] font-bold text-surface-400 uppercase tracking-widest">SSL Expiry & Infrastructure Alerts</p>
          </div>
        </div>
        <button
          onClick={() => setIsEnabled(!isEnabled)}
          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none ${isEnabled ? 'bg-brand-600' : 'bg-surface-200'}`}
        >
          <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${isEnabled ? 'translate-x-6' : 'translate-x-1'}`} />
        </button>
      </div>

      <div className="p-6 space-y-8">
        {/* Recipients Section */}
        <section className="space-y-4">
          <div className="flex items-center gap-2">
            <Mail className="h-4 w-4 text-brand-600" />
            <h4 className="text-xs font-black text-surface-900 uppercase tracking-widest">Alert Recipients</h4>
          </div>
          
          <div className="flex gap-2">
            <div className="relative flex-1">
              <input
                type="email"
                placeholder="Enter alert email..."
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && addEmail()}
                className="input pl-10 h-10 text-xs"
              />
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-surface-300" />
            </div>
            <button 
              onClick={addEmail}
              className="btn-primary h-10 px-4 aspect-square flex items-center justify-center"
            >
              <Plus className="h-4 w-4" />
            </button>
          </div>

          <div className="flex flex-wrap gap-2">
            {emails.length === 0 ? (
              <p className="text-[10px] text-surface-400 font-medium italic">No custom recipients added. Primary account holder will be notified.</p>
            ) : (
              emails.map(email => (
                <div key={email} className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-50 border border-surface-200 text-surface-600 text-[11px] font-bold">
                  {email}
                  <button onClick={() => removeEmail(email)} className="text-surface-400 hover:text-red-500 transition-colors">
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))
            )}
          </div>
        </section>

        {/* Thresholds Section */}
        <section className="space-y-4 font-mono">
          <div className="flex items-center gap-2">
            <Calendar className="h-4 w-4 text-brand-600" />
            <h4 className="text-xs font-black text-surface-900 uppercase tracking-widest">Notification Schedule</h4>
          </div>
          
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
            {DEFAULT_THRESHOLDS.map(days => (
              <button
                key={days}
                onClick={() => toggleThreshold(days)}
                className={`py-2 px-3 rounded-xl border text-[10px] font-black tracking-tight transition-all ${
                  thresholds.includes(days)
                    ? 'bg-brand-50 border-brand-200 text-brand-700 shadow-sm'
                    : 'border-surface-200 text-surface-400 hover:bg-surface-50'
                }`}
              >
                {days} DAYS BEFORE
              </button>
            ))}
          </div>
          <p className="text-[10px] text-surface-400 leading-relaxed uppercase tracking-wider font-bold">
            Alerts will be dispatched via Resend Cloud to all registered endpoints when the certificate enters these maturity phases.
          </p>
        </section>

        <div className="pt-4 flex items-center justify-between border-t border-surface-100">
          <div className="flex items-center gap-2">
            {saveStatus === "success" && (
              <div className="flex items-center gap-1.5 text-emerald-600 animate-in fade-in zoom-in-95">
                <CheckCircle2 className="h-4 w-4" />
                <span className="text-[10px] font-black uppercase tracking-widest">Settings Synchronized</span>
              </div>
            )}
            {saveStatus === "error" && (
              <div className="flex items-center gap-1.5 text-red-600 animate-in shake duration-500">
                <AlertCircle className="h-4 w-4" />
                <span className="text-[10px] font-black uppercase tracking-widest">Sync Failed</span>
              </div>
            )}
            {saveStatus === "saving" && (
              <div className="flex items-center gap-1.5 text-brand-600 animate-pulse">
                <Spinner size="sm" />
                <span className="text-[10px] font-black uppercase tracking-widest">Saving Preferences...</span>
              </div>
            )}
          </div>
          
          <button
            onClick={handleSave}
            disabled={saveStatus === "saving" || !isEnabled}
            className="btn-primary px-8 py-3 text-[11px] font-black tracking-[0.2em] shadow-xl shadow-brand-100"
          >
            UPDATE MONITORING
          </button>
        </div>
      </div>
    </div>
  );
}
