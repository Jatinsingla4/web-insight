import { cn } from "@/lib/cn";

type Status = "success" | "warning" | "danger" | "info" | "neutral" | "pending";

interface StatusBadgeProps {
  status: Status;
  label: string;
  className?: string;
}

const statusStyles: Record<Status, string> = {
  success: "badge-success",
  warning: "badge-warning",
  danger: "badge-danger",
  info: "badge-info",
  neutral: "badge-neutral",
  pending: "badge bg-purple-50 text-purple-700 ring-1 ring-purple-600/20",
};

export function StatusBadge({ status, label, className }: StatusBadgeProps) {
  return (
    <span className={cn(statusStyles[status], className)}>
      {label}
    </span>
  );
}
