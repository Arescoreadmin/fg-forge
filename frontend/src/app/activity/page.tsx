"use client";

import { useState } from "react";
import Link from "next/link";
import { StatusBadge, TrackBadge } from "@/components/StatusBadge";
import {
  Activity,
  Clock,
  Filter,
  ChevronRight,
  Search,
  RefreshCw,
} from "lucide-react";
import type { ScenarioState, Track, ScenarioStatus } from "@/types";
import { clsx } from "clsx";

// Mock data for demo
const mockScenarios: ScenarioState[] = [
  {
    scenario_id: "scn_001",
    request_id: "req_001",
    track: "netplus",
    subject: "alice@cyber.io",
    tenant_id: "tenant_001",
    tier: "standard",
    status: "completed",
    network_id: "net_001",
    containers: [],
    created_at: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    updated_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
    completion_reason: "success",
    error: null,
  },
  {
    scenario_id: "scn_002",
    request_id: "req_002",
    track: "ccna",
    subject: "bob@network.io",
    tenant_id: "tenant_001",
    tier: "premium",
    status: "running",
    network_id: "net_002",
    containers: ["worker", "attacker"],
    created_at: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    updated_at: new Date().toISOString(),
    completed_at: null,
    completion_reason: null,
    error: null,
  },
  {
    scenario_id: "scn_003",
    request_id: "req_003",
    track: "cissp",
    subject: "charlie@sec.io",
    tenant_id: "tenant_002",
    tier: "enterprise",
    status: "failed",
    network_id: null,
    containers: [],
    created_at: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 28).toISOString(),
    completed_at: null,
    completion_reason: null,
    error: "OPA policy denied",
  },
  {
    scenario_id: "scn_004",
    request_id: "req_004",
    track: "netplus",
    subject: "diana@ops.io",
    tenant_id: "tenant_001",
    tier: "basic",
    status: "completed",
    network_id: "net_004",
    containers: [],
    created_at: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    completed_at: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    completion_reason: "success",
    error: null,
  },
  {
    scenario_id: "scn_005",
    request_id: "req_005",
    track: "ccna",
    subject: "evan@cloud.io",
    tenant_id: "tenant_003",
    tier: "standard",
    status: "pending",
    network_id: null,
    containers: [],
    created_at: new Date(Date.now() - 1000 * 60 * 2).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 2).toISOString(),
    completed_at: null,
    completion_reason: null,
    error: null,
  },
  {
    scenario_id: "scn_006",
    request_id: "req_006",
    track: "cissp",
    subject: "fiona@risk.io",
    tenant_id: "tenant_002",
    tier: "enterprise",
    status: "completed",
    network_id: "net_006",
    containers: [],
    created_at: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    completed_at: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    completion_reason: "success",
    error: null,
  },
];

function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`;
  return `${Math.floor(seconds / 86400)} days ago`;
}

export default function ActivityPage() {
  const [scenarios, setScenarios] = useState<ScenarioState[]>(mockScenarios);
  const [filterTrack, setFilterTrack] = useState<Track | "all">("all");
  const [filterStatus, setFilterStatus] = useState<ScenarioStatus | "all">("all");
  const [searchQuery, setSearchQuery] = useState("");

  const filteredScenarios = scenarios.filter((s) => {
    if (filterTrack !== "all" && s.track !== filterTrack) return false;
    if (filterStatus !== "all" && s.status !== filterStatus) return false;
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        s.scenario_id.toLowerCase().includes(query) ||
        s.subject?.toLowerCase().includes(query) ||
        s.track.toLowerCase().includes(query)
      );
    }
    return true;
  });

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-display font-bold text-frost-dark-100 flex items-center gap-3">
            <Activity className="w-8 h-8 text-frost-orange-400" />
            Activity
          </h1>
          <p className="mt-2 text-frost-dark-400">
            All scenario activity and history
          </p>
        </div>
        <button className="btn-ghost inline-flex items-center gap-2 text-sm py-2 self-start">
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="card p-4 mb-6">
        <div className="flex flex-col sm:flex-row gap-4">
          {/* Search */}
          <div className="flex-1 relative">
            <Search
              size={18}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-frost-dark-500"
            />
            <input
              type="text"
              placeholder="Search by ID, subject, or track..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input pl-10"
            />
          </div>

          {/* Track Filter */}
          <div className="flex items-center gap-2">
            <Filter size={16} className="text-frost-dark-500" />
            <select
              value={filterTrack}
              onChange={(e) => setFilterTrack(e.target.value as Track | "all")}
              className="select w-36"
            >
              <option value="all">All Tracks</option>
              <option value="netplus">NetPlus</option>
              <option value="ccna">CCNA</option>
              <option value="cissp">CISSP</option>
            </select>
          </div>

          {/* Status Filter */}
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value as ScenarioStatus | "all")}
            className="select w-36"
          >
            <option value="all">All Status</option>
            <option value="pending">Pending</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
          </select>
        </div>
      </div>

      {/* Results Count */}
      <p className="text-frost-dark-500 text-sm mb-4">
        Showing {filteredScenarios.length} of {scenarios.length} scenarios
      </p>

      {/* Scenarios Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-frost-dark-800/50">
              <tr>
                <th className="table-header">Scenario</th>
                <th className="table-header hidden md:table-cell">Subject</th>
                <th className="table-header">Track</th>
                <th className="table-header">Status</th>
                <th className="table-header hidden sm:table-cell">Created</th>
                <th className="table-header w-12"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-frost-dark-800">
              {filteredScenarios.map((scenario) => (
                <tr key={scenario.scenario_id} className="table-row">
                  <td className="table-cell">
                    <span className="font-mono text-frost-dark-200">
                      {scenario.scenario_id}
                    </span>
                  </td>
                  <td className="table-cell hidden md:table-cell">
                    <span className="text-frost-dark-400">
                      {scenario.subject || "—"}
                    </span>
                  </td>
                  <td className="table-cell">
                    <TrackBadge track={scenario.track} />
                  </td>
                  <td className="table-cell">
                    <StatusBadge status={scenario.status} />
                  </td>
                  <td className="table-cell hidden sm:table-cell">
                    <span className="text-frost-dark-500 text-sm flex items-center gap-1">
                      <Clock size={14} />
                      {formatTimeAgo(scenario.created_at)}
                    </span>
                  </td>
                  <td className="table-cell">
                    <Link
                      href={`/scenarios/${scenario.scenario_id}`}
                      className="p-2 text-frost-dark-500 hover:text-frost-orange-400 transition-colors inline-block"
                    >
                      <ChevronRight size={18} />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredScenarios.length === 0 && (
          <div className="px-6 py-12 text-center">
            <p className="text-frost-dark-500">No scenarios match your filters</p>
            <button
              onClick={() => {
                setFilterTrack("all");
                setFilterStatus("all");
                setSearchQuery("");
              }}
              className="btn-ghost mt-4 text-sm py-2"
            >
              Clear Filters
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
