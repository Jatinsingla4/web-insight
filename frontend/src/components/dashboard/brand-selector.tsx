"use client";

import { useState, useRef, useEffect } from "react";
import { 
  ChevronDown, 
  Globe, 
  Plus, 
  Settings, 
  Zap, 
  Check,
  Search,
  LayoutGrid
} from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { trpc } from "@/lib/trpc";
import { Spinner } from "@/components/ui/spinner";
import { AddBrandModal } from "./add-brand-modal";
import type { Brand } from "@dns-checker/shared";

export function BrandSelector() {
  const [isOpen, setIsOpen] = useState(false);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const dropdownRef = useRef<HTMLDivElement>(null);
  
  const router = useRouter();
  const searchParams = useSearchParams();
  const brandId = searchParams.get("brandId");
  const mode = searchParams.get("mode");

  const brandsQuery = trpc.brand.list.useQuery({ limit: 100 });
  const brands = brandsQuery.data?.items ?? [];
  const selectedBrand = brands.find((b: Brand) => b.id === brandId);

  // Close dropdown on click outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const filteredBrands = brands.filter((b: Brand) => 
    b.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    b.domain.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleSelect = (id: string) => {
    setIsOpen(false);
    router.push(`/dashboard?brandId=${id}`);
  };

  const handleMode = (newMode: string) => {
    setIsOpen(false);
    router.push(`/dashboard?mode=${newMode}`);
  };

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`flex items-center gap-2 px-3 py-2 rounded-xl border transition-all duration-300 ${
          isOpen 
            ? "border-brand-200 bg-brand-50/50 ring-2 ring-brand-100" 
            : "border-surface-200 bg-white hover:border-brand-200 hover:bg-surface-50"
        }`}
      >
        <div className="h-6 w-6 rounded-lg bg-brand-600 flex items-center justify-center shrink-0">
          <Globe className="h-3.5 w-3.5 text-white" />
        </div>
        <div className="text-left hidden sm:block">
          <p className="text-[10px] font-black text-surface-400 uppercase tracking-widest leading-none mb-0.5">
            Active Brand
          </p>
          <p className="text-xs font-bold text-surface-900 truncate max-w-[120px]">
            {mode === "manage" ? "Portfolio Hub" : 
             mode === "quick" ? "Live Analysis" : 
             selectedBrand?.name || "Select Brand"}
          </p>
        </div>
        <ChevronDown className={`h-4 w-4 text-surface-400 transition-transform duration-300 ${isOpen ? "rotate-180" : ""}`} />
      </button>

      {isOpen && (
        <div className="absolute top-full left-0 mt-2 w-[280px] bg-white rounded-2xl border border-surface-200 shadow-2xl shadow-surface-200/50 z-50 overflow-hidden animate-in fade-in zoom-in-95 duration-200 origin-top-left">
          {/* Header Actions */}
          <div className="p-2 border-b border-surface-100 bg-surface-50/50 flex flex-col gap-1">
            <button
               onClick={() => handleMode("manage")}
               className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-bold transition-colors ${
                 mode === "manage" ? "bg-brand-600 text-white" : "text-surface-600 hover:bg-white hover:text-brand-600"
               }`}
            >
              <LayoutGrid className="h-4 w-4" />
              Manage Portfolio
            </button>
            <button
               onClick={() => handleMode("quick")}
               className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-bold transition-colors ${
                 mode === "quick" ? "bg-brand-600 text-white" : "text-surface-600 hover:bg-white hover:text-brand-600"
               }`}
            >
              <Zap className="h-4 w-4" />
              Quick Analysis
            </button>
          </div>

          {/* Search */}
          <div className="px-3 py-2 border-b border-surface-100 flex items-center gap-2">
            <Search className="h-3.5 w-3.5 text-surface-400" />
            <input 
              type="text"
              placeholder="Search brands..."
              autoFocus
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-transparent border-none focus:ring-0 text-xs font-medium text-surface-900 placeholder:text-surface-400"
            />
          </div>

          {/* Brand List */}
          <div className="max-h-[300px] overflow-y-auto p-1 py-1.5 custom-scrollbar">
            {brandsQuery.isLoading ? (
              <div className="py-8 flex justify-center">
                <Spinner size="sm" />
              </div>
            ) : filteredBrands.length === 0 ? (
              <p className="px-3 py-4 text-center text-xs text-surface-400 font-medium">
                No matching brands found
              </p>
            ) : (
              <div className="space-y-0.5">
                {filteredBrands.map((brand: Brand) => (
                  <button
                    key={brand.id}
                    onClick={() => handleSelect(brand.id)}
                    className={`w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded-xl transition-all ${
                      brandId === brand.id 
                        ? "bg-brand-50 text-brand-600" 
                        : "text-surface-600 hover:bg-surface-50"
                    }`}
                  >
                    <div className="min-w-0 text-left">
                      <p className="text-xs font-bold truncate">{brand.name}</p>
                      <p className="text-[10px] font-mono opacity-60 truncate">{brand.domain}</p>
                    </div>
                    {brandId === brand.id && <Check className="h-3.5 w-3.5 shrink-0" />}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Footer Footer */}
          <div className="p-1 border-t border-surface-100 bg-surface-50/50">
            <button
              onClick={() => {
                setIsOpen(false);
                setIsAddModalOpen(true);
              }}
              className="w-full flex items-center gap-2 px-3 py-3 rounded-xl text-xs font-black text-brand-600 hover:bg-brand-600 hover:text-white transition-all uppercase tracking-widest group"
            >
              <Plus className="h-4 w-4 group-hover:rotate-90 transition-transform" />
              Add Domain to Fleets
            </button>
          </div>
        </div>
      )}

      {isAddModalOpen && (
        <AddBrandModal 
          onClose={() => setIsAddModalOpen(false)} 
          onSuccess={() => {
            setIsAddModalOpen(false);
            brandsQuery.refetch();
          }}
        />
      )}
    </div>
  );
}
