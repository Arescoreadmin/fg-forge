"use client";

import { useState } from "react";
import { TrackBadge } from "@/components/StatusBadge";
import { Trophy, Medal, Award, ChevronDown, User } from "lucide-react";
import type { Track, LeaderboardEntry } from "@/types";
import { clsx } from "clsx";

// Mock data for demo
const mockLeaderboard: Record<Track, LeaderboardEntry[]> = {
  netplus: [
    { rank: 1, scenario_id: "scn_001", subject: "alice@cyber.io", score: 0.98, passed: 19, total: 20, completed_at: new Date().toISOString() },
    { rank: 2, scenario_id: "scn_002", subject: "bob@security.net", score: 0.95, passed: 19, total: 20, completed_at: new Date().toISOString() },
    { rank: 3, scenario_id: "scn_003", subject: "charlie@ops.com", score: 0.93, passed: 18, total: 20, completed_at: new Date().toISOString() },
    { rank: 4, scenario_id: "scn_004", subject: "diana@tech.io", score: 0.90, passed: 18, total: 20, completed_at: new Date().toISOString() },
    { rank: 5, scenario_id: "scn_005", subject: "evan@cloud.net", score: 0.88, passed: 17, total: 20, completed_at: new Date().toISOString() },
    { rank: 6, scenario_id: "scn_006", subject: "fiona@dev.com", score: 0.85, passed: 17, total: 20, completed_at: new Date().toISOString() },
    { rank: 7, scenario_id: "scn_007", subject: "george@infra.io", score: 0.83, passed: 16, total: 20, completed_at: new Date().toISOString() },
    { rank: 8, scenario_id: "scn_008", subject: "helen@sys.net", score: 0.80, passed: 16, total: 20, completed_at: new Date().toISOString() },
  ],
  ccna: [
    { rank: 1, scenario_id: "scn_101", subject: "network@pro.io", score: 0.97, passed: 29, total: 30, completed_at: new Date().toISOString() },
    { rank: 2, scenario_id: "scn_102", subject: "cisco@expert.net", score: 0.93, passed: 28, total: 30, completed_at: new Date().toISOString() },
    { rank: 3, scenario_id: "scn_103", subject: "router@admin.com", score: 0.90, passed: 27, total: 30, completed_at: new Date().toISOString() },
    { rank: 4, scenario_id: "scn_104", subject: "switch@ops.io", score: 0.87, passed: 26, total: 30, completed_at: new Date().toISOString() },
    { rank: 5, scenario_id: "scn_105", subject: "vlan@tech.net", score: 0.83, passed: 25, total: 30, completed_at: new Date().toISOString() },
  ],
  cissp: [
    { rank: 1, scenario_id: "scn_201", subject: "ciso@enterprise.io", score: 0.96, passed: 48, total: 50, completed_at: new Date().toISOString() },
    { rank: 2, scenario_id: "scn_202", subject: "security@corp.net", score: 0.92, passed: 46, total: 50, completed_at: new Date().toISOString() },
    { rank: 3, scenario_id: "scn_203", subject: "risk@mgmt.com", score: 0.88, passed: 44, total: 50, completed_at: new Date().toISOString() },
  ],
};

const trackTabs: { id: Track; label: string }[] = [
  { id: "netplus", label: "Network+" },
  { id: "ccna", label: "CCNA" },
  { id: "cissp", label: "CISSP" },
];

function getRankIcon(rank: number) {
  switch (rank) {
    case 1:
      return <Trophy className="w-5 h-5 text-amber-400" />;
    case 2:
      return <Medal className="w-5 h-5 text-slate-300" />;
    case 3:
      return <Award className="w-5 h-5 text-amber-600" />;
    default:
      return <span className="w-5 h-5 flex items-center justify-center text-frost-dark-500 font-mono text-sm">{rank}</span>;
  }
}

function getRankStyle(rank: number) {
  switch (rank) {
    case 1:
      return "bg-amber-500/10 border-amber-500/30";
    case 2:
      return "bg-slate-400/10 border-slate-400/30";
    case 3:
      return "bg-amber-600/10 border-amber-600/30";
    default:
      return "";
  }
}

export default function LeaderboardPage() {
  const [selectedTrack, setSelectedTrack] = useState<Track>("netplus");
  const leaderboard = mockLeaderboard[selectedTrack];

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-display font-bold text-frost-dark-100 flex items-center gap-3">
          <Trophy className="w-8 h-8 text-frost-orange-400" />
          Leaderboard
        </h1>
        <p className="mt-2 text-frost-dark-400">
          Top performers across certification tracks
        </p>
      </div>

      {/* Track Tabs */}
      <div className="mb-8">
        <div className="flex flex-wrap gap-2">
          {trackTabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setSelectedTrack(tab.id)}
              className={clsx(
                "px-5 py-2.5 rounded-lg font-display font-medium text-sm uppercase tracking-wider transition-all duration-200",
                selectedTrack === tab.id
                  ? "bg-frost-dark-700 text-frost-orange-400 shadow-ember"
                  : "bg-frost-dark-800/50 text-frost-dark-400 hover:bg-frost-dark-800 hover:text-frost-dark-200"
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Top 3 Podium */}
      <div className="grid grid-cols-3 gap-4 mb-8">
        {leaderboard.slice(0, 3).map((entry, idx) => {
          const podiumOrder = [1, 0, 2]; // Center the 1st place
          const displayEntry = leaderboard[podiumOrder[idx]];
          if (!displayEntry) return null;

          const isFirst = displayEntry.rank === 1;

          return (
            <div
              key={displayEntry.scenario_id}
              className={clsx(
                "card p-6 text-center",
                getRankStyle(displayEntry.rank),
                isFirst && "md:-mt-4"
              )}
            >
              <div className="flex justify-center mb-3">
                {getRankIcon(displayEntry.rank)}
              </div>
              <div className="w-12 h-12 mx-auto mb-3 rounded-full bg-frost-dark-700 flex items-center justify-center">
                <User className="w-6 h-6 text-frost-dark-400" />
              </div>
              <p className="text-frost-dark-200 font-medium text-sm truncate">
                {displayEntry.subject || "Anonymous"}
              </p>
              <p
                className={clsx(
                  "text-2xl font-display font-bold mt-2",
                  isFirst ? "text-amber-400" : "text-frost-dark-200"
                )}
              >
                {(displayEntry.score * 100).toFixed(1)}%
              </p>
              <p className="text-frost-dark-500 text-xs mt-1">
                {displayEntry.passed}/{displayEntry.total} passed
              </p>
            </div>
          );
        })}
      </div>

      {/* Full Leaderboard Table */}
      <div className="card overflow-hidden">
        <div className="px-6 py-4 border-b border-frost-dark-700 flex items-center justify-between">
          <h2 className="font-display font-semibold text-frost-dark-200 uppercase tracking-wider">
            All Rankings
          </h2>
          <TrackBadge track={selectedTrack} />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-frost-dark-800/50">
              <tr>
                <th className="table-header w-16">Rank</th>
                <th className="table-header">Subject</th>
                <th className="table-header text-right">Score</th>
                <th className="table-header text-right hidden sm:table-cell">Passed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-frost-dark-800">
              {leaderboard.map((entry) => (
                <tr key={entry.scenario_id} className="table-row">
                  <td className="table-cell">
                    <div className="flex items-center justify-center">
                      {getRankIcon(entry.rank)}
                    </div>
                  </td>
                  <td className="table-cell">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-frost-dark-700 flex items-center justify-center flex-shrink-0">
                        <User className="w-4 h-4 text-frost-dark-500" />
                      </div>
                      <div>
                        <p className="text-frost-dark-200 font-medium">
                          {entry.subject || "Anonymous"}
                        </p>
                        <p className="text-frost-dark-500 text-xs font-mono">
                          {entry.scenario_id}
                        </p>
                      </div>
                    </div>
                  </td>
                  <td className="table-cell text-right">
                    <span
                      className={clsx(
                        "font-display font-bold",
                        entry.score >= 0.9
                          ? "text-emerald-400"
                          : entry.score >= 0.8
                          ? "text-frost-orange-400"
                          : "text-frost-dark-300"
                      )}
                    >
                      {(entry.score * 100).toFixed(1)}%
                    </span>
                  </td>
                  <td className="table-cell text-right hidden sm:table-cell">
                    <span className="text-frost-dark-400">
                      {entry.passed}/{entry.total}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
