"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { StatusBadge, TrackBadge } from "@/components/StatusBadge";
import {
  ArrowLeft,
  Clock,
  Terminal,
  FileCheck,
  Download,
  Shield,
  CheckCircle,
  XCircle,
  Loader2,
  ExternalLink,
  Copy,
  Check,
} from "lucide-react";
import type { ScenarioState, ScoreResult } from "@/types";
import { clsx } from "clsx";

// Mock data for demo
const mockScenario: ScenarioState = {
  scenario_id: "scn_abc123",
  request_id: "req_001",
  track: "netplus",
  subject: "user@example.com",
  tenant_id: "tenant_001",
  tier: "standard",
  status: "completed",
  network_id: "net_001",
  containers: ["worker_agent", "attacker_agent", "aux_device1"],
  created_at: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
  updated_at: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
  completed_at: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
  completion_reason: "success",
  error: null,
};

const mockScore: ScoreResult = {
  scenario_id: "scn_abc123",
  track: "netplus",
  score: 0.85,
  passed: 17,
  total: 20,
  criteria: [
    { criterion_id: "ping_test", passed: true, weight: 0.1, weighted_score: 0.1 },
    { criterion_id: "dns_resolution", passed: true, weight: 0.15, weighted_score: 0.15 },
    { criterion_id: "routing_config", passed: true, weight: 0.2, weighted_score: 0.2 },
    { criterion_id: "firewall_rules", passed: false, weight: 0.15, weighted_score: 0 },
    { criterion_id: "vlan_setup", passed: true, weight: 0.1, weighted_score: 0.1 },
    { criterion_id: "nat_config", passed: true, weight: 0.1, weighted_score: 0.1 },
    { criterion_id: "dhcp_config", passed: false, weight: 0.1, weighted_score: 0 },
    { criterion_id: "security_audit", passed: true, weight: 0.1, weighted_score: 0.1 },
  ],
  computed_at: new Date().toISOString(),
};

function formatDateTime(dateString: string): string {
  return new Date(dateString).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatDuration(start: string, end: string | null): string {
  if (!end) return "In progress...";
  const ms = new Date(end).getTime() - new Date(start).getTime();
  const minutes = Math.floor(ms / 60000);
  const seconds = Math.floor((ms % 60000) / 1000);
  return `${minutes}m ${seconds}s`;
}

export default function ScenarioDetailPage() {
  const params = useParams();
  const scenarioId = params.id as string;

  const [scenario, setScenario] = useState<ScenarioState | null>(mockScenario);
  const [score, setScore] = useState<ScoreResult | null>(mockScore);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  // TODO: Replace with actual API calls
  // useEffect(() => {
  //   async function fetchData() {
  //     setLoading(true);
  //     const [scenarioData, scoreData] = await Promise.all([
  //       api.getScenario(scenarioId),
  //       api.getScore(scenarioId).catch(() => null),
  //     ]);
  //     setScenario(scenarioData);
  //     setScore(scoreData);
  //     setLoading(false);
  //   }
  //   fetchData();
  // }, [scenarioId]);

  async function copyToClipboard(text: string) {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  if (loading || !scenario) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-16 text-center">
        <Loader2 className="w-8 h-8 animate-spin mx-auto text-frost-orange-400" />
        <p className="text-frost-dark-400 mt-4">Loading scenario...</p>
      </div>
    );
  }

  const isCompleted = scenario.status === "completed" || scenario.status === "completed_with_errors";

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Back Link */}
      <Link
        href="/"
        className="inline-flex items-center gap-2 text-frost-dark-400 hover:text-frost-dark-200 text-sm mb-6 transition-colors"
      >
        <ArrowLeft size={16} />
        Back to Dashboard
      </Link>

      {/* Header */}
      <div className="card p-6 mb-6">
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <TrackBadge track={scenario.track} />
              <StatusBadge status={scenario.status} />
            </div>
            <h1 className="text-2xl font-display font-bold text-frost-dark-100 flex items-center gap-2">
              {scenario.scenario_id}
              <button
                onClick={() => copyToClipboard(scenario.scenario_id)}
                className="p-1 text-frost-dark-500 hover:text-frost-dark-300 transition-colors"
              >
                {copied ? <Check size={16} /> : <Copy size={16} />}
              </button>
            </h1>
            {scenario.subject && (
              <p className="text-frost-dark-400 mt-1">{scenario.subject}</p>
            )}
          </div>
          <div className="flex gap-3">
            {isCompleted && (
              <button className="btn-ghost inline-flex items-center gap-2 text-sm py-2">
                <Download size={16} />
                Evidence
              </button>
            )}
          </div>
        </div>

        {/* Meta Info */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6 pt-6 border-t border-frost-dark-700">
          <div>
            <p className="text-frost-dark-500 text-xs uppercase tracking-wider">Created</p>
            <p className="text-frost-dark-200 text-sm mt-1">
              {formatDateTime(scenario.created_at)}
            </p>
          </div>
          <div>
            <p className="text-frost-dark-500 text-xs uppercase tracking-wider">Duration</p>
            <p className="text-frost-dark-200 text-sm mt-1">
              {formatDuration(scenario.created_at, scenario.completed_at)}
            </p>
          </div>
          <div>
            <p className="text-frost-dark-500 text-xs uppercase tracking-wider">Tier</p>
            <p className="text-frost-dark-200 text-sm mt-1 capitalize">
              {scenario.tier || "Unknown"}
            </p>
          </div>
          <div>
            <p className="text-frost-dark-500 text-xs uppercase tracking-wider">Containers</p>
            <p className="text-frost-dark-200 text-sm mt-1">
              {scenario.containers.length} active
            </p>
          </div>
        </div>
      </div>

      {/* Score Card */}
      {score && (
        <div className="card mb-6 overflow-hidden">
          <div className="px-6 py-4 border-b border-frost-dark-700 flex items-center justify-between">
            <h2 className="font-display font-semibold text-frost-dark-200 uppercase tracking-wider flex items-center gap-2">
              <FileCheck size={18} />
              Score Results
            </h2>
            <span
              className={clsx(
                "text-2xl font-display font-bold",
                score.score >= 0.9
                  ? "text-emerald-400"
                  : score.score >= 0.7
                  ? "text-frost-orange-400"
                  : "text-red-400"
              )}
            >
              {(score.score * 100).toFixed(1)}%
            </span>
          </div>

          {/* Score Progress Bar */}
          <div className="px-6 py-4 bg-frost-dark-800/30">
            <div className="flex items-center justify-between text-sm mb-2">
              <span className="text-frost-dark-400">
                {score.passed} of {score.total} criteria passed
              </span>
              <span className="text-frost-dark-500">
                {((score.passed / score.total) * 100).toFixed(0)}%
              </span>
            </div>
            <div className="progress-bar">
              <div
                className="progress-bar-fill"
                style={{ width: `${(score.passed / score.total) * 100}%` }}
              />
            </div>
          </div>

          {/* Criteria List */}
          <div className="divide-y divide-frost-dark-800">
            {score.criteria.map((criterion) => (
              <div
                key={criterion.criterion_id}
                className="px-6 py-3 flex items-center justify-between"
              >
                <div className="flex items-center gap-3">
                  {criterion.passed ? (
                    <CheckCircle className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-400" />
                  )}
                  <span className="text-frost-dark-200 font-mono text-sm">
                    {criterion.criterion_id.replace(/_/g, " ")}
                  </span>
                </div>
                <div className="flex items-center gap-4">
                  <span className="text-frost-dark-500 text-xs">
                    Weight: {(criterion.weight * 100).toFixed(0)}%
                  </span>
                  <span
                    className={clsx(
                      "text-sm font-medium",
                      criterion.passed ? "text-emerald-400" : "text-red-400"
                    )}
                  >
                    {criterion.passed ? `+${(criterion.weighted_score * 100).toFixed(0)}%` : "0%"}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Containers */}
      {scenario.containers.length > 0 && (
        <div className="card">
          <div className="px-6 py-4 border-b border-frost-dark-700">
            <h2 className="font-display font-semibold text-frost-dark-200 uppercase tracking-wider flex items-center gap-2">
              <Terminal size={18} />
              Containers
            </h2>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {scenario.containers.map((container) => (
                <div
                  key={container}
                  className="px-4 py-3 bg-frost-dark-800 rounded-lg flex items-center gap-3"
                >
                  <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-frost-dark-200 font-mono text-sm">
                    {container}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Security Info */}
      <div className="mt-6 p-4 bg-frost-blue-600/10 border border-frost-blue-500/20 rounded-lg">
        <div className="flex items-start gap-3">
          <Shield className="w-5 h-5 text-frost-blue-400 mt-0.5" />
          <div>
            <p className="text-frost-blue-300 font-medium text-sm">Isolated Environment</p>
            <p className="text-frost-blue-400/70 text-sm mt-1">
              This scenario ran in a fully isolated network with deny-all egress policy.
              All evidence is cryptographically signed and hash-chained for audit compliance.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
