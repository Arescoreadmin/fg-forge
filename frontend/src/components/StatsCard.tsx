"use client";

import { clsx } from "clsx";
import type { LucideIcon } from "lucide-react";

interface StatsCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: LucideIcon;
  trend?: {
    value: number;
    label: string;
  };
  variant?: "default" | "ember" | "frost";
}

export function StatsCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  variant = "default",
}: StatsCardProps) {
  return (
    <div
      className={clsx(
        "card p-6 relative overflow-hidden",
        variant === "ember" && "border-frost-orange-500/30",
        variant === "frost" && "border-frost-blue-500/30"
      )}
    >
      {/* Background glow for variants */}
      {variant === "ember" && (
        <div className="absolute inset-0 bg-gradient-to-br from-frost-orange-500/5 to-transparent pointer-events-none" />
      )}
      {variant === "frost" && (
        <div className="absolute inset-0 bg-gradient-to-br from-frost-blue-500/5 to-transparent pointer-events-none" />
      )}

      <div className="relative">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-frost-dark-400 text-sm font-display uppercase tracking-wider">
              {title}
            </p>
            <p
              className={clsx(
                "text-3xl font-display font-bold mt-2",
                variant === "ember" && "text-frost-orange-400",
                variant === "frost" && "text-frost-blue-400",
                variant === "default" && "text-frost-dark-100"
              )}
            >
              {value}
            </p>
            {subtitle && (
              <p className="text-frost-dark-500 text-sm mt-1">{subtitle}</p>
            )}
          </div>
          {Icon && (
            <div
              className={clsx(
                "p-3 rounded-lg",
                variant === "ember" && "bg-frost-orange-500/10 text-frost-orange-400",
                variant === "frost" && "bg-frost-blue-500/10 text-frost-blue-400",
                variant === "default" && "bg-frost-dark-700 text-frost-dark-400"
              )}
            >
              <Icon size={24} />
            </div>
          )}
        </div>

        {trend && (
          <div className="mt-4 flex items-center gap-2">
            <span
              className={clsx(
                "text-sm font-medium",
                trend.value > 0 ? "text-emerald-400" : "text-red-400"
              )}
            >
              {trend.value > 0 ? "+" : ""}
              {trend.value}%
            </span>
            <span className="text-frost-dark-500 text-sm">{trend.label}</span>
          </div>
        )}
      </div>
    </div>
  );
}
