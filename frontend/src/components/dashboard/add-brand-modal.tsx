"use client";

import { useState, type FormEvent } from "react";
import { X, Globe } from "lucide-react";
import { trpc } from "@/lib/trpc";
import { Spinner } from "@/components/ui/spinner";

interface AddBrandModalProps {
  onClose: () => void;
  onSuccess: (domain: string) => void;
}

export function AddBrandModal({ onClose, onSuccess }: AddBrandModalProps) {
  const [domain, setDomain] = useState("");
  const [name, setName] = useState("");

  const createMutation = trpc.brand.create.useMutation({
    onSuccess: (data) => {
      onSuccess(data.domain);
    },
  });

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!domain.trim() || !name.trim()) return;
    createMutation.mutate({
      domain: domain.trim(),
      name: name.trim(),
    });
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal */}
      <div className="relative bg-white rounded-xl shadow-xl w-full max-w-md mx-4 animate-slide-up">
        <div className="flex items-center justify-between p-6 border-b border-surface-200">
          <h2 className="text-lg font-semibold text-surface-900">
            Add Brand to Monitor
          </h2>
          <button
            onClick={onClose}
            className="p-1 rounded-md hover:bg-surface-100 transition-colors"
            aria-label="Close"
          >
            <X className="h-5 w-5 text-surface-400" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label
              htmlFor="brand-name"
              className="block text-sm font-medium text-surface-700 mb-1.5"
            >
              Brand Name
            </label>
            <input
              id="brand-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Company"
              className="input"
              autoFocus
            />
          </div>

          <div>
            <label
              htmlFor="brand-domain"
              className="block text-sm font-medium text-surface-700 mb-1.5"
            >
              Domain
            </label>
            <div className="relative">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-surface-400" />
              <input
                id="brand-domain"
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="example.com"
                className="input pl-11"
              />
            </div>
          </div>

          {createMutation.error && (
            <p className="text-sm text-red-600">
              {createMutation.error.message}
            </p>
          )}

          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="btn-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={
                !domain.trim() ||
                !name.trim() ||
                createMutation.isPending
              }
              className="btn-primary gap-2"
            >
              {createMutation.isPending && (
                <Spinner size="sm" className="text-white" />
              )}
              Add & Scan
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
