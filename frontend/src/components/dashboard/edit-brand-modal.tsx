"use client";
 
import { useState, type FormEvent } from "react";
import { X, Globe, Type } from "lucide-react";
import { trpc } from "@/lib/trpc";
import { Spinner } from "@/components/ui/spinner";
import type { Brand } from "@dns-checker/shared";
 
interface EditBrandModalProps {
  brand: Brand;
  onClose: () => void;
  onSuccess: () => void;
}
 
export function EditBrandModal({ brand, onClose, onSuccess }: EditBrandModalProps) {
  const [name, setName] = useState(brand.name);
  const [domain, setDomain] = useState(brand.domain);
 
  const updateMutation = trpc.brand.update.useMutation({
    onSuccess: () => {
      onSuccess();
    },
  });
 
  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || !domain.trim() || updateMutation.isPending) return;
 
    updateMutation.mutate({
      id: brand.id,
      name: name.trim(),
      domain: domain.trim(),
    });
  }
 
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-surface-900/40 backdrop-blur-sm animate-fade-in">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md overflow-hidden border border-surface-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-surface-100 bg-surface-50/50">
          <h3 className="text-base font-bold text-surface-900 uppercase tracking-wider">
            Edit Brand Details
          </h3>
          <button
            onClick={onClose}
            className="p-2 hover:bg-surface-200 rounded-lg transition-colors"
          >
            <X className="h-4 w-4 text-surface-500" />
          </button>
        </div>
 
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          <div className="space-y-2">
            <label className="text-[10px] font-bold text-surface-400 uppercase tracking-widest pl-1">
              Brand Name
            </label>
            <div className="relative">
              <Type className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-surface-300" />
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. My Website"
                className="input pl-10"
                required
                disabled={updateMutation.isPending}
              />
            </div>
          </div>
 
          <div className="space-y-2">
            <label className="text-[10px] font-bold text-surface-400 uppercase tracking-widest pl-1">
              Primary Domain
            </label>
            <div className="relative">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-surface-300" />
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="e.g. example.com"
                className="input pl-10 font-mono"
                required
                disabled={updateMutation.isPending}
              />
            </div>
          </div>
 
          {updateMutation.error && (
            <p className="text-xs text-red-600 bg-red-50 p-2 rounded border border-red-100">
              {updateMutation.error.message}
            </p>
          )}
 
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 btn-secondary"
              disabled={updateMutation.isPending}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex-1 btn-primary"
              disabled={updateMutation.isPending}
            >
              {updateMutation.isPending ? (
                <Spinner size="sm" className="text-white mx-auto" />
              ) : (
                "Save Changes"
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
