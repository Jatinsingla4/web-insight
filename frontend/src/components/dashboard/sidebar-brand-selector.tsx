"use client";

import { useState, useRef, useEffect } from "react";
import { 
  ChevronDown, 
  Globe, 
  Plus, 
  Check,
  Search,
  LayoutGrid
} from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { trpc } from "@/lib/trpc";
import { Spinner } from "@/components/ui/spinner";
import { AddBrandModal } from "./add-brand-modal";
import type { Brand } from "@dns-checker/shared";

interface SidebarBrandSelectorProps {
  isCollapsed?: boolean;
}

export function SidebarBrandSelector({ isCollapsed }: SidebarBrandSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const dropdownRef = useRef<HTMLDivElement>(null);
  
  const router = useRouter();
  const searchParams = useSearchParams();
  const brandId = searchParams.get("brandId");

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

  return (
    <div className="relative mb-6" ref={dropdownRef}>
      {!isCollapsed && (
        <p className="text-[10px] font-black text-surface-400 uppercase tracking-[0.2em] px-3 mb-2 animate-in fade-in duration-300">
          Active Project
        </p>
      )}
      
      <button
        onClick={() => setIsOpen(!isOpen)}
        title={isCollapsed ? selectedBrand?.name || "Select Project" : ""}
        className={`w-full flex items-center justify-between gap-3 p-3 rounded-xl border transition-all duration-300 ${
          isOpen 
            ? "border-brand-200 bg-brand-50 shadow-lg shadow-brand-100" 
            : "border-surface-200 bg-white hover:border-brand-100 hover:bg-surface-50"
        } ${isCollapsed ? "px-2 justify-center" : "px-3"}`}
      >
        <div className={`flex items-center gap-2 min-w-0 ${isCollapsed ? "justify-center" : ""}`}>
          <div className="h-7 w-7 rounded-lg bg-brand-600 flex items-center justify-center shrink-0">
             <Globe className="h-4 w-4 text-white" />
          </div>
          {!isCollapsed && (
            <div className="text-left hidden lg:block min-w-0 animate-in fade-in duration-300">
              <p className="text-xs font-bold text-surface-900 truncate">
                 {selectedBrand?.name || "Select Project"}
              </p>
            </div>
          )}
        </div>
        {!isCollapsed && (
          <ChevronDown className={`h-4 w-4 text-surface-400 transition-transform duration-300 ${isOpen ? "rotate-180" : ""} hidden lg:block`} />
        )}
      </button>

      {isOpen && (
        <div className="absolute top-full left-0 mt-2 w-72 bg-white rounded-2xl border border-surface-200 shadow-2xl z-50 overflow-hidden animate-in fade-in zoom-in-95 duration-200 origin-top-left">
          {/* Search */}
          <div className="px-3 py-2 border-b border-surface-100 flex items-center gap-2 bg-surface-50/50">
            <Search className="h-3.5 w-3.5 text-surface-400" />
            <input 
              type="text"
              placeholder="Search domain assets..."
              autoFocus
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-transparent border-none focus:ring-0 text-xs font-medium text-surface-900 placeholder:text-surface-400"
            />
          </div>

          {/* Brand List */}
          <div className="max-h-64 overflow-y-auto p-1 py-1.5 scrollbar-thin">
            {brandsQuery.isLoading ? (
              <div className="py-8 flex justify-center">
                <Spinner size="sm" />
              </div>
            ) : filteredBrands.length === 0 ? (
              <p className="px-3 py-4 text-center text-xs text-surface-400 font-medium">
                No matching projects found
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

          {/* Add Brand Action */}
          <div className="p-1 border-t border-surface-100">
            <button
              onClick={() => {
                setIsOpen(false);
                setIsAddModalOpen(true);
              }}
              className="w-full flex items-center gap-2 px-3 py-3 rounded-xl text-xs font-black text-brand-600 hover:bg-brand-50 transition-all uppercase tracking-widest"
            >
              <Plus className="h-4 w-4" />
              New Asset Registration
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
