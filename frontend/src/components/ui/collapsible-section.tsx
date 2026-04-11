import React, { useState } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";
import { cn } from "@/lib/cn";

interface CollapsibleSectionProps {
  title: string;
  subtitle?: string;
  icon?: React.ReactNode;
  badge?: React.ReactNode;
  children: React.ReactNode;
  defaultExpanded?: boolean;
  className?: string;
  headerClassName?: string;
}

export function CollapsibleSection({
  title,
  subtitle,
  icon,
  badge,
  children,
  defaultExpanded = true,
  className,
  headerClassName,
}: CollapsibleSectionProps) {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  return (
    <section 
      className={cn(
        "card transition-all duration-500", 
        isExpanded ? "overflow-visible" : "overflow-hidden pb-0",
        className
      )}
    >
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className={cn(
          "w-full flex items-center justify-between p-6 text-left hover:bg-surface-50/50 transition-colors group",
          headerClassName
        )}
      >
        <div className="flex items-center gap-4">
          {icon && (
            <div className="h-10 w-10 rounded-xl bg-surface-100 flex items-center justify-center text-surface-600 group-hover:scale-110 transition-transform duration-500">
              {icon}
            </div>
          )}
          <div className="flex flex-col gap-0.5">
            <div className="flex items-center gap-3">
              <h3 className="text-sm font-bold text-surface-900 uppercase tracking-wider">
                {title}
              </h3>
              {badge}
            </div>
            {subtitle && (
              <p className="text-xs text-surface-500 font-medium leading-relaxed">
                {subtitle}
              </p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className={cn(
            "h-8 w-8 rounded-full border border-surface-200 flex items-center justify-center text-surface-400 group-hover:border-brand-300 group-hover:text-brand-600 transition-all duration-500",
            isExpanded ? "rotate-180" : "rotate-0"
          )}>
            <ChevronDown className="h-4 w-4" />
          </div>
        </div>
      </button>

      <div 
        className={cn(
          "transition-all duration-500 ease-in-out",
          isExpanded ? "max-h-[5000px] opacity-100 p-6 pt-0 overflow-visible" : "max-h-0 opacity-0 pointer-events-none overflow-hidden"
        )}
      >
        <div className="border-t border-surface-100 pt-6">
          {children}
        </div>
      </div>
    </section>
  );
}
