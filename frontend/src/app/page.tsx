"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ShieldLogo } from "@/components/ShieldLogo";
import { StatsCard } from "@/components/StatsCard";
import { StatusBadge, TrackBadge } from "@/components/StatusBadge";
import {
  Zap,
  Trophy,
  Target,
  Clock,
  ChevronRight,
  Play,
  TrendingUp,
} from "lucide-react";
import type { ScenarioState, AggregateStats } from "@/types";

// Mock data for demo - replace with API calls
const mockScenarios: ScenarioState[] = [
  {
    scenario_id: "scn_abc123",
    request_id: "req_001",
    track: "netplus",
    subject: "user@example.com",
    tenant_id: "tenant_001",
    tier: "standard",
    status: "running",
    network_id: "net_001",
    containers: ["worker", "attacker"],
    created_at: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    updated_at: new Date().toISOString(),
    completed_at: null,
    completion_reason: null,
    error: null,
  },
  {
    scenario_id: "scn_def456",
    request_id: "req_002",
    track: "ccna",
    subject: "admin@corp.io",
    tenant_id: "tenant_001",
    tier: "premium",
    status: "completed",
    network_id: "net_002",
    containers: [],
    created_at: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    completed_at: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    completion_reason: "success",
    error: null,
  },
  {
    scenario_id: "scn_ghi789",
    request_id: "req_003",
    track: "cissp",
    subject: "security@firm.net",
    tenant_id: "tenant_002",
    tier: "enterprise",
    status: "failed",
    network_id: null,
    containers: [],
    created_at: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 115).toISOString(),
    completed_at: null,
    completion_reason: null,
    error: "Template validation failed",
  },
];

const mockStats: AggregateStats = {
  total_scenarios: 1247,
  completed_scenarios: 1089,
  average_score: 0.847,
  scores_by_track: {
    netplus: 412,
    ccna: 389,
    cissp: 288,
  },
};

function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default function DashboardPage() {
  const [scenarios, setScenarios] = useState<ScenarioState[]>(mockScenarios);
  const [stats, setStats] = useState<AggregateStats>(mockStats);
  const [loading, setLoading] = useState(false);

  // TODO: Replace with actual API calls
  // useEffect(() => {
  //   async function fetchData() {
  //     setLoading(true);
  //     const [scenariosData, statsData] = await Promise.all([
  //       api.listScenarios(),
  //       api.getStats(),
  //     ]);
  //     setScenarios(scenariosData);
  //     setStats(statsData);
  //     setLoading(false);
  //   }
  //   fetchData();
  // }, []);

  const runningScenarios = scenarios.filter((s) => s.status === "running");
  const recentScenarios = scenarios.slice(0, 5);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Hero Section */}
      <div className="mb-12">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-6">
          <div>
            <h1 className="text-3xl md:text-4xl font-display font-bold text-frost-dark-100">
              Welcome to the <span className="gradient-text">Forge</span>
            </h1>
            <p className="mt-2 text-frost-dark-400 text-lg">
              High-isolation training scenarios with deterministic scoring
            </p>
          </div>
          <Link href="/spawn" className="btn-primary inline-flex items-center gap-2">
            <Zap size={18} />
            Spawn Scenario
          </Link>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
        <StatsCard
          title="Total Scenarios"
          value={stats.total_scenarios.toLocaleString()}
          icon={Target}
          trend={{ value: 12, label: "vs last week" }}
        />
        <StatsCard
          title="Completed"
          value={stats.completed_scenarios.toLocaleString()}
          subtitle={`${((stats.completed_scenarios / stats.total_scenarios) * 100).toFixed(1)}% completion rate`}
          icon={Trophy}
          variant="frost"
        />
        <StatsCard
          title="Avg. Score"
          value={`${(stats.average_score * 100).toFixed(1)}%`}
          icon={TrendingUp}
          variant="ember"
        />
        <StatsCard
          title="Active Now"
          value={runningScenarios.length}
          subtitle="scenarios running"
          icon={Play}
        />
      </div>

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Recent Scenarios */}
        <div className="lg:col-span-2">
          <div className="card">
            <div className="px-6 py-4 border-b border-frost-dark-700 flex items-center justify-between">
              <h2 className="font-display font-semibold text-frost-dark-200 uppercase tracking-wider">
                Recent Scenarios
              </h2>
              <Link
                href="/activity"
                className="text-frost-orange-400 hover:text-frost-orange-300 text-sm font-display uppercase tracking-wider inline-flex items-center gap-1"
              >
                View All
                <ChevronRight size={16} />
              </Link>
            </div>
            <div className="divide-y divide-frost-dark-800">
              {recentScenarios.map((scenario) => (
                <Link
                  key={scenario.scenario_id}
                  href={`/scenarios/${scenario.scenario_id}`}
                  className="table-row flex items-center justify-between px-6 py-4"
                >
                  <div className="flex items-center gap-4">
                    <div className="hidden sm:block">
                      <TrackBadge track={scenario.track} />
                    </div>
                    <div>
                      <p className="text-frost-dark-200 font-mono text-sm">
                        {scenario.scenario_id}
                      </p>
                      <p className="text-frost-dark-500 text-xs mt-0.5">
                        {scenario.subject || "anonymous"}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="hidden sm:block text-frost-dark-500 text-xs">
                      <Clock size={12} className="inline mr-1" />
                      {formatTimeAgo(scenario.created_at)}
                    </div>
                    <StatusBadge status={scenario.status} />
                  </div>
                </Link>
              ))}
              {recentScenarios.length === 0 && (
                <div className="px-6 py-12 text-center">
                  <p className="text-frost-dark-500">No scenarios yet</p>
                  <Link href="/spawn" className="btn-secondary mt-4 inline-flex items-center gap-2">
                    <Zap size={16} />
                    Spawn Your First
                  </Link>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Track Breakdown */}
        <div className="lg:col-span-1">
          <div className="card">
            <div className="px-6 py-4 border-b border-frost-dark-700">
              <h2 className="font-display font-semibold text-frost-dark-200 uppercase tracking-wider">
                By Track
              </h2>
            </div>
            <div className="p-6 space-y-6">
              {/* NetPlus */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <TrackBadge track="netplus" />
                  <span className="text-frost-dark-300 font-mono text-sm">
                    {stats.scores_by_track.netplus}
                  </span>
                </div>
                <div className="progress-bar">
                  <div
                    className="progress-bar-fill"
                    style={{
                      width: `${(stats.scores_by_track.netplus / stats.completed_scenarios) * 100}%`,
                    }}
                  />
                </div>
              </div>

              {/* CCNA */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <TrackBadge track="ccna" />
                  <span className="text-frost-dark-300 font-mono text-sm">
                    {stats.scores_by_track.ccna}
                  </span>
                </div>
                <div className="progress-bar">
                  <div
                    className="progress-bar-fill"
                    style={{
                      width: `${(stats.scores_by_track.ccna / stats.completed_scenarios) * 100}%`,
                    }}
                  />
                </div>
              </div>

              {/* CISSP */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <TrackBadge track="cissp" />
                  <span className="text-frost-dark-300 font-mono text-sm">
                    {stats.scores_by_track.cissp}
                  </span>
                </div>
                <div className="progress-bar">
                  <div
                    className="progress-bar-fill"
                    style={{
                      width: `${(stats.scores_by_track.cissp / stats.completed_scenarios) * 100}%`,
                    }}
                  />
                </div>
              </div>

              <div className="pt-4 border-t border-frost-dark-700">
                <Link
                  href="/leaderboard"
                  className="btn-ghost w-full justify-center inline-flex items-center gap-2 text-sm py-2"
                >
                  <Trophy size={16} />
                  View Leaderboards
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
