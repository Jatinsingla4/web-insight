"use client";

import { useState } from "react";
import {
  Globe,
  RefreshCw,
  Trash2,
  Clock,
  ChevronRight,
  Plus,
  ArrowLeft,
  Zap,
} from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { trpc } from "@/lib/trpc";
import { Spinner } from "@/components/ui/spinner";
import { StatusBadge } from "@/components/ui/status-badge";
import { AddBrandModal } from "./add-brand-modal";
import { EditBrandModal } from "./edit-brand-modal";
import type { Brand } from "@dns-checker/shared";

interface BrandListProps {
  onBrandCreated?: (domain: string) => void;
}
 
export function BrandList({ onBrandCreated }: BrandListProps) {
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const router = useRouter();
  const searchParams = useSearchParams();
  const brandId = searchParams.get("brandId");

  const brandsQuery = trpc.brand.list.useQuery(
    { limit: 50 },
    {
      refetchInterval: (query) => {
        const brands = query.state.data?.items ?? [];
        // Support polling if any brand is still in 'QUEUED' state (null lastScannedAt)
        const hasQueued = brands.some((b: Brand) => !b.lastScannedAt);
        return hasQueued ? 5000 : false;
      },
    }
  );
  const brands = brandsQuery.data?.items ?? [];

  const isSidebar = !!brandId;

  if (brandsQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Spinner size="lg" />
      </div>
    );
  }

  if (brandsQuery.error) {
    return (
      <div className="card p-6 text-center">
        <p className="text-sm text-red-600">
          Failed to load brands: {brandsQuery.error.message}
        </p>
        <button
          onClick={() => brandsQuery.refetch()}
          className="btn-secondary mt-3"
        >
          Retry
        </button>
      </div>
    );
  }

  if (brands.length === 0) {
    return (
      <div className="card p-12 text-center border-2 border-dashed border-surface-200 bg-surface-50/30">
        <Globe className="h-12 w-12 text-surface-300 mx-auto mb-4 animate-pulse" />
        <h3 className="text-base font-bold text-surface-900 mb-2 uppercase tracking-wider">
          Your Brand Portfolio is Empty
        </h3>
        <p className="text-sm text-surface-500 max-w-sm mx-auto mb-8 leading-relaxed">
          Active monitoring starts here. Add your first brand domain to begin tracking infrastructure health, security compliance, and tech stack evolution.
        </p>
        <button
          onClick={() => setIsAddModalOpen(true)}
          className="btn-primary gap-2 shadow-lg shadow-brand-200"
        >
          <Plus className="h-4 w-4" />
          Register New Brand
        </button>
        {isAddModalOpen && (
          <AddBrandModal
            onClose={() => setIsAddModalOpen(false)}
            onSuccess={(domain) => {
              setIsAddModalOpen(false);
              brandsQuery.refetch();
              onBrandCreated?.(domain);
            }}
          />
        )}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {isSidebar && (
            <button 
              onClick={() => router.push('/dashboard')}
              className="p-1.5 hover:bg-surface-100 rounded-lg text-surface-500 transition-colors"
              title="Back to Grid"
            >
              <ArrowLeft className="h-4 w-4" />
            </button>
          )}
          <h2 className={`font-bold text-surface-900 uppercase tracking-tight ${isSidebar ? 'text-xs' : 'text-lg'}`}>
            {isSidebar ? 'Portfolio' : 'Monitored Brands'}
          </h2>
        </div>
        {isSidebar ? (
          <button
            onClick={() => router.push('/dashboard?mode=quick')}
            className="p-1.5 hover:bg-brand-50 rounded-lg text-brand-600 transition-colors border border-transparent hover:border-brand-100"
            title="Quick Analysis"
          >
            <Zap className="h-3.5 w-3.5 fill-current" />
          </button>
        ) : (
          <button
            onClick={() => setIsAddModalOpen(true)}
            className="btn-primary gap-2 py-2 text-xs"
          >
            <Plus className="h-4 w-4" />
            ADD BRAND
          </button>
        )}
      </div>

      <div className={isSidebar ? "flex flex-col gap-2" : "grid grid-cols-1 lg:grid-cols-2 gap-4"}>
        {brands.map((brand: Brand) => (
          <BrandCard
            key={brand.id}
            brand={brand}
            isSidebar={isSidebar}
            isSelected={brandId === brand.id}
            onSelect={() => router.push(`/dashboard?brandId=${brand.id}`)}
            onUpdate={() => brandsQuery.refetch()}
          />
        ))}
        {isSidebar && (
          <button
            onClick={() => setIsAddModalOpen(true)}
            className="w-full flex items-center justify-center gap-2 p-3 rounded-xl border border-dashed border-surface-200 text-surface-400 hover:text-brand-600 hover:border-brand-200 hover:bg-brand-50/30 transition-all text-xs font-bold uppercase tracking-wider mt-2 group"
          >
            <Plus className="h-3.5 w-3.5 group-hover:rotate-90 transition-transform" />
            Add Brand
          </button>
        )}
      </div>

      {isAddModalOpen && (
        <AddBrandModal
          onClose={() => setIsAddModalOpen(false)}
          onSuccess={(domain) => {
            setIsAddModalOpen(false);
            brandsQuery.refetch();
            onBrandCreated?.(domain);
          }}
        />
      )}
    </div>
  );
}

function BrandCard({
  brand,
  isSidebar,
  isSelected,
  onSelect,
  onUpdate,
}: {
  brand: Brand;
  isSidebar: boolean;
  isSelected: boolean;
  onSelect: () => void;
  onUpdate: () => void;
}) {
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const deleteMutation = trpc.brand.delete.useMutation();
  const utils = trpc.useUtils();
  const router = useRouter();

  if (isSidebar) {
    return (
      <div className="relative group">
        <button
          onClick={onSelect}
          className={`w-full flex items-center gap-3 p-3 rounded-xl transition-all duration-300 ${
            isSelected 
              ? 'bg-brand-600 text-white shadow-md shadow-brand-100 ring-2 ring-brand-500 ring-offset-1' 
              : 'hover:bg-brand-50/50 border border-transparent hover:border-brand-100'
          }`}
        >
          <div className={`h-8 w-8 rounded-lg flex items-center justify-center shrink-0 ${isSelected ? 'bg-white/20' : 'bg-brand-50 text-brand-600'}`}>
            <Globe className="h-4 w-4" />
          </div>
          <div className="min-w-0 flex-1 text-left">
            <p className={`text-[11px] font-black truncate uppercase tracking-tight ${isSelected ? 'text-white' : 'text-surface-900'}`}>
              {brand.name}
            </p>
            <p className={`text-[9px] font-mono truncate ${isSelected ? 'text-brand-100' : 'text-brand-500'}`}>
              {brand.domain}
            </p>
          </div>
          {isSelected && <ChevronRight className="h-3 w-3 text-white/50" />}
        </button>
        
        {/* Context Menu for Sidebar (Edit/Delete) */}
        <div className={`absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1 transition-opacity ${isSelected ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}>
           <button 
             onClick={(e) => { e.stopPropagation(); setIsEditModalOpen(true); }}
             className={`p-1 rounded border border-transparent transition-colors ${isSelected ? 'hover:bg-white/10 text-white' : 'hover:bg-white text-surface-400 hover:text-brand-600 hover:border-surface-200'}`}
             title="Edit Brand"
           >
             <Plus className="h-3 w-3 rotate-45" />
           </button>
           <button 
             onClick={async (e) => { 
               e.stopPropagation(); 
               if (window.confirm(`Delete "${brand.name}" and all historical data?`)) {
                 await deleteMutation.mutateAsync({ id: brand.id });
                 utils.brand.list.invalidate();
                 if (isSelected) router.push('/dashboard');
               }
             }}
             disabled={deleteMutation.isPending}
             className={`p-1 rounded border border-transparent transition-colors ${isSelected ? 'hover:bg-white/10 text-white' : 'hover:bg-white text-red-400 hover:text-red-600 hover:border-red-100'}`}
             title="Purge Brand"
           >
             {deleteMutation.isPending ? <Spinner size="sm" /> : <Trash2 className="h-3 w-3" />}
           </button>
        </div>

        {isEditModalOpen && (
          <EditBrandModal
            brand={brand}
            onClose={() => setIsEditModalOpen(false)}
            onSuccess={() => {
              setIsEditModalOpen(false);
              onUpdate();
            }}
          />
        )}
      </div>
    );
  }

  return (
    <div className={`card overflow-hidden transition-all duration-300 ${isSelected ? 'ring-2 ring-brand-500 shadow-xl' : 'hover:border-brand-200'}`}>
      <button
        onClick={onSelect}
        className="w-full flex items-center gap-4 p-5 text-left hover:bg-surface-50/50 transition-colors"
      >
        <div className={`h-12 w-12 rounded-xl flex items-center justify-center shrink-0 transition-colors ${isSelected ? 'bg-brand-600 text-white' : 'bg-brand-50 text-brand-600'}`}>
          <Globe className="h-6 w-6" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-bold text-surface-900 truncate uppercase tracking-tight">
            {brand.name}
          </p>
          <p className="text-xs text-brand-500 font-mono truncate mt-0.5">
            {brand.domain}
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {brand.lastScannedAt ? (
            <div className="bg-surface-100 px-2 py-1 rounded text-[10px] font-bold text-surface-500 uppercase flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {formatRelativeTime(brand.lastScannedAt)}
            </div>
          ) : (
            <StatusBadge status="pending" label="QUEUED" />
          )}
          <ChevronRight
            className={`h-4 w-4 text-surface-300 transition-transform duration-300 ${
              isSelected ? "rotate-90 text-brand-500" : ""
            }`}
          />
        </div>
      </button>

      {isSelected && (
        <div className="border-t border-surface-100 px-4 py-3 bg-surface-50/80 flex items-center justify-between gap-2 animate-slide-down">
          <div className="flex items-center gap-2">
            <button
              onClick={(e) => {
                e.stopPropagation();
                onSelect(); // This will trigger the BrandDashboard view via URL params
              }}
              className="btn-primary py-1.5 px-4 h-auto text-[10px] font-black tracking-widest shadow-sm"
            >
              VIEW ANALYSIS
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setIsEditModalOpen(true);
              }}
              className="btn-ghost gap-1.5 text-[11px] font-bold py-1.5 h-auto text-surface-600 hover:bg-white border border-transparent hover:border-surface-200"
            >
              <Plus className="h-3.5 w-3.5 rotate-45" />
              EDIT
            </button>
          </div>
          
          <button
            onClick={async (e) => {
              e.stopPropagation();
              if (
                window.confirm(
                  `CRITICAL: Are you sure you want to delete "${brand.name}" and all historical scan records?`,
                )
              ) {
                await deleteMutation.mutateAsync({ id: brand.id });
                utils.brand.list.invalidate();
                if (isSelected) router.push('/dashboard');
              }
            }}
            disabled={deleteMutation.isPending}
            className="btn-ghost text-red-600 hover:bg-red-50 gap-1.5 text-[11px] font-bold py-1.5 h-auto"
          >
            <Trash2 className="h-3.5 w-3.5" />
            PURGE
          </button>
        </div>
      )}

      {isEditModalOpen && (
        <EditBrandModal
          brand={brand}
          onClose={() => setIsEditModalOpen(false)}
          onSuccess={() => {
            setIsEditModalOpen(false);
            onUpdate();
          }}
        />
      )}
    </div>
  );
}

function formatRelativeTime(isoString: string): string {
  const date = new Date(isoString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60_000);

  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;

  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 30) return `${diffDays}d ago`;

  return date.toLocaleDateString();
}
