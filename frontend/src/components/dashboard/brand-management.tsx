"use client";

import { useState } from "react";
import { 
  Globe, 
  Trash2, 
  Plus, 
  ExternalLink,
  Search,
  MoreVertical,
  Activity,
  Settings2,
  Zap,
  AlertCircle
} from "lucide-react";
import { useRouter } from "next/navigation";
import { trpc } from "@/lib/trpc";
import { Spinner } from "@/components/ui/spinner";
import { StatusBadge } from "@/components/ui/status-badge";
import { EditBrandModal } from "./edit-brand-modal";
import { AddBrandModal } from "./add-brand-modal";
import type { Brand } from "@dns-checker/shared";

export function BrandManagement() {
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [editingBrand, setEditingBrand] = useState<Brand | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  
  const router = useRouter();
  const utils = trpc.useUtils();
  const brandsQuery = trpc.brand.list.useQuery({ limit: 100 });
  const deleteMutation = trpc.brand.delete.useMutation();

  const brands = brandsQuery.data?.items ?? [];
  const filteredBrands = brands.filter((b: Brand) => 
    b.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    b.domain.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleDelete = async (brand: Brand) => {
    if (window.confirm(`CRITICAL: Are you sure you want to purge "${brand.name}"? This will delete all historical data.`)) {
      await deleteMutation.mutateAsync({ id: brand.id });
      utils.brand.list.invalidate();
    }
  };

  if (brandsQuery.isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 animate-pulse">
        <Spinner size="lg" />
        <p className="mt-4 text-surface-400 font-mono text-[11px] font-black uppercase tracking-widest">Hydrating Portfolio...</p>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-black text-surface-900 uppercase tracking-tighter">Brand Portfolio</h2>
          <p className="text-surface-500 font-medium italic">Manage your monitored infrastructure, update domain settings, or add new brand assets to your security fleet.</p>
        </div>
        <button
          onClick={() => setIsAddModalOpen(true)}
          className="btn-primary gap-2 h-11 px-6 shadow-xl shadow-brand-100"
        >
          <Plus className="h-4 w-4" />
          Register New Brand
        </button>
      </div>

      <div className="card border-surface-200/60 overflow-hidden shadow-2xl shadow-surface-200/20 bg-white">
        <div className="px-6 py-4 border-b border-surface-100 bg-surface-50/50 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="relative w-full sm:w-[320px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-surface-400" />
            <input 
              type="text"
              placeholder="Filter by name or domain..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-white border-surface-200 rounded-xl pl-10 h-10 text-sm focus:ring-brand-500 focus:border-brand-500 transition-all font-medium"
            />
          </div>
          <div className="flex items-center gap-4 text-[11px] font-black uppercase tracking-widest text-surface-400">
            <span className="flex items-center gap-1.5"><Activity className="h-3.5 w-3.5" /> Total Scans: {brands.length}</span>
            <span className="h-4 w-px bg-surface-200" />
            <span className="flex items-center gap-1.5"><Zap className="h-3.5 w-3.5" /> Fleet Capacity: 100%</span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-surface-50/50 border-b border-surface-100">
                <th className="px-6 py-4 text-left text-[10px] font-black text-surface-400 uppercase tracking-[0.2em]">Domain Asset</th>
                <th className="px-6 py-4 text-left text-[10px] font-black text-surface-400 uppercase tracking-[0.2em] hidden md:table-cell">Health Status</th>
                <th className="px-6 py-4 text-left text-[10px] font-black text-surface-400 uppercase tracking-[0.2em] hidden lg:table-cell">Last Sync</th>
                <th className="px-6 py-4 text-right text-[10px] font-black text-surface-400 uppercase tracking-[0.2em]">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-100">
              {filteredBrands.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-6 py-12 text-center">
                    <div className="flex flex-col items-center gap-2">
                       <AlertCircle className="h-8 w-8 text-surface-300" />
                       <p className="text-sm font-bold text-surface-900">No matching domain assets found</p>
                       <p className="text-xs text-surface-400">Try adjusting your filters or add a new brandasset.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredBrands.map((brand: Brand) => (
                  <tr key={brand.id} className="group hover:bg-surface-50/50 transition-colors">
                    <td className="px-6 py-5">
                      <div className="flex items-center gap-3">
                        <div className="h-10 w-10 rounded-xl bg-brand-50 flex items-center justify-center text-brand-600 group-hover:bg-brand-600 group-hover:text-white transition-colors duration-300 shadow-sm border border-brand-100 group-hover:border-brand-500">
                          <Globe className="h-5 w-5" />
                        </div>
                        <div className="min-w-0">
                          <p className="text-sm font-bold text-surface-900 uppercase tracking-tight">{brand.name}</p>
                          <p className="text-[11px] font-mono text-brand-500 truncate">{brand.domain}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-5 hidden md:table-cell">
                      {brand.lastScannedAt ? (
                        <StatusBadge status="success" label="SYNCED" />
                      ) : (
                        <StatusBadge status="pending" label="INITIALIZING" />
                      )}
                    </td>
                    <td className="px-6 py-5 hidden lg:table-cell">
                      <p className="text-[11px] font-mono font-bold text-surface-500">
                        {brand.lastScannedAt ? new Date(brand.lastScannedAt).toLocaleString() : "---"}
                      </p>
                    </td>
                    <td className="px-6 py-5 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => router.push(`/dashboard?brandId=${brand.id}`)}
                          className="p-2 rounded-lg bg-surface-100 text-surface-500 hover:bg-brand-600 hover:text-white transition-all shadow-sm border border-surface-200 hover:border-brand-500"
                          title="View Analysis"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => setEditingBrand(brand)}
                          className="p-2 rounded-lg bg-surface-100 text-surface-500 hover:bg-surface-200 hover:text-surface-900 transition-all shadow-sm border border-surface-200 hover:border-surface-300"
                          title="Edit Brand"
                        >
                          <Settings2 className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(brand)}
                          disabled={deleteMutation.isPending}
                          className="p-2 rounded-lg bg-surface-100 text-red-400 hover:bg-red-600 hover:text-white transition-all shadow-sm border border-surface-200 hover:border-red-500"
                          title="Purge Brand"
                        >
                          {deleteMutation.isPending ? <Spinner size="sm" /> : <Trash2 className="h-4 w-4" />}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {isAddModalOpen && (
        <AddBrandModal 
          onClose={() => setIsAddModalOpen(false)} 
          onSuccess={() => {
            setIsAddModalOpen(false);
            utils.brand.list.invalidate();
          }}
        />
      )}

      {editingBrand && (
        <EditBrandModal
          brand={editingBrand}
          onClose={() => setEditingBrand(null)}
          onSuccess={() => {
            setEditingBrand(null);
            utils.brand.list.invalidate();
          }}
        />
      )}
    </div>
  );
}
