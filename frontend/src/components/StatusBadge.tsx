"use client";

import { clsx } from "clsx";
import type { ScenarioStatus, Track } from "@/types";

interface StatusBadgeProps {
  status: ScenarioStatus;
}

const statusConfig: Record<ScenarioStatus, { label: string; className: string }> = {
  pending: { label: "Pending", className: "badge-pending" },
  creating: { label: "Creating", className: "badge-info" },
  running: { label: "Running", className: "badge-warning" },
  completed: { label: "Completed", className: "badge-success" },
  completed_with_errors: { label: "Completed", className: "badge-warning" },
  failed: { label: "Failed", className: "badge-error" },
  timeout: { label: "Timeout", className: "badge-error" },
};

export function StatusBadge({ status }: StatusBadgeProps) {
  const config = statusConfig[status] || statusConfig.pending;

  return (
    <span className={config.className}>
      {status === "running" && (
        <span className="mr-1.5 h-2 w-2 rounded-full bg-current animate-pulse" />
      )}
      {config.label}
    </span>
  );
}

interface TrackBadgeProps {
  track: Track;
}

const trackConfig: Record<Track, { label: string; className: string }> = {
  netplus: { label: "NetPlus", className: "track-netplus" },
  ccna: { label: "CCNA", className: "track-ccna" },
  cissp: { label: "CISSP", className: "track-cissp" },
};

export function TrackBadge({ track }: TrackBadgeProps) {
  const config = trackConfig[track] || { label: track, className: "badge" };

  return <span className={config.className}>{config.label}</span>;
}
