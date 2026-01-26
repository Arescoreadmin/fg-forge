"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldLogo } from "@/components/ShieldLogo";
import {
  Zap,
  Shield,
  Network,
  Lock,
  ChevronRight,
  Loader2,
  Check,
  AlertCircle,
} from "lucide-react";
import type { Track, SpawnResponse } from "@/types";
import { api } from "@/lib/api";
import { clsx } from "clsx";

interface TrackOption {
  id: Track;
  name: string;
  description: string;
  icon: typeof Shield;
  color: "emerald" | "blue" | "purple";
  tier: string;
}

const tracks: TrackOption[] = [
  {
    id: "netplus",
    name: "Network+",
    description: "Foundation networking concepts, protocols, and troubleshooting",
    icon: Network,
    color: "emerald",
    tier: "Foundation",
  },
  {
    id: "ccna",
    name: "CCNA",
    description: "Cisco networking, routing, switching, and network security",
    icon: Shield,
    color: "blue",
    tier: "Professional",
  },
  {
    id: "cissp",
    name: "CISSP",
    description: "Information security management and best practices",
    icon: Lock,
    color: "purple",
    tier: "Expert",
  },
];

const colorClasses = {
  emerald: {
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/30",
    borderActive: "border-emerald-500",
    text: "text-emerald-400",
    glow: "shadow-[0_0_30px_rgba(16,185,129,0.2)]",
  },
  blue: {
    bg: "bg-frost-blue-500/10",
    border: "border-frost-blue-500/30",
    borderActive: "border-frost-blue-500",
    text: "text-frost-blue-400",
    glow: "shadow-[0_0_30px_rgba(30,58,95,0.3)]",
  },
  purple: {
    bg: "bg-purple-500/10",
    border: "border-purple-500/30",
    borderActive: "border-purple-500",
    text: "text-purple-400",
    glow: "shadow-[0_0_30px_rgba(168,85,247,0.2)]",
  },
};

export default function SpawnPage() {
  const router = useRouter();
  const [selectedTrack, setSelectedTrack] = useState<Track | null>(null);
  const [subject, setSubject] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<SpawnResponse | null>(null);

  async function handleSpawn() {
    if (!selectedTrack) return;

    setLoading(true);
    setError(null);

    try {
      // For demo, simulate API call
      // const response = await api.spawn({
      //   track: selectedTrack,
      //   subject: subject || undefined,
      // });

      // Simulated response for demo
      await new Promise((resolve) => setTimeout(resolve, 1500));
      const response: SpawnResponse = {
        request_id: `req_${Math.random().toString(36).slice(2, 10)}`,
        scenario_id: `scn_${Math.random().toString(36).slice(2, 10)}`,
        access_url: "https://forge.frostgate.io/access/...",
        access_token: "tok_demo...",
        expires_at: new Date(Date.now() + 1000 * 60 * 30).toISOString(),
        sat: "sat_demo...",
      };

      setSuccess(response);

      // Redirect to scenario after brief delay
      setTimeout(() => {
        router.push(`/scenarios/${response.scenario_id}`);
      }, 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to spawn scenario");
    } finally {
      setLoading(false);
    }
  }

  if (success) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-16">
        <div className="card p-8 text-center">
          <div className="w-16 h-16 mx-auto mb-6 rounded-full bg-emerald-500/20 flex items-center justify-center">
            <Check className="w-8 h-8 text-emerald-400" />
          </div>
          <h1 className="text-2xl font-display font-bold text-frost-dark-100 mb-2">
            Scenario Spawned
          </h1>
          <p className="text-frost-dark-400 mb-6">
            Your {selectedTrack?.toUpperCase()} scenario is being created
          </p>
          <div className="bg-frost-dark-900 rounded-lg p-4 font-mono text-sm text-frost-dark-300 mb-6">
            {success.scenario_id}
          </div>
          <p className="text-frost-dark-500 text-sm">
            Redirecting to scenario...
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-display font-bold text-frost-dark-100">
          Spawn Training Scenario
        </h1>
        <p className="mt-2 text-frost-dark-400">
          Select a certification track to begin your isolated training environment
        </p>
      </div>

      {/* Track Selection */}
      <div className="mb-8">
        <label className="block text-frost-dark-300 font-display text-sm uppercase tracking-wider mb-4">
          Select Track
        </label>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {tracks.map((track) => {
            const colors = colorClasses[track.color];
            const Icon = track.icon;
            const isSelected = selectedTrack === track.id;

            return (
              <button
                key={track.id}
                onClick={() => setSelectedTrack(track.id)}
                className={clsx(
                  "card-hover p-6 text-left transition-all duration-300",
                  isSelected && [colors.borderActive, colors.glow]
                )}
              >
                <div
                  className={clsx(
                    "w-12 h-12 rounded-lg flex items-center justify-center mb-4",
                    colors.bg
                  )}
                >
                  <Icon className={clsx("w-6 h-6", colors.text)} />
                </div>
                <h3 className="font-display font-semibold text-frost-dark-100 text-lg">
                  {track.name}
                </h3>
                <p className="text-frost-dark-500 text-sm mt-1 mb-3">
                  {track.description}
                </p>
                <span
                  className={clsx(
                    "inline-block px-2 py-1 rounded text-xs font-display uppercase tracking-wider",
                    colors.bg,
                    colors.text
                  )}
                >
                  {track.tier}
                </span>
                {isSelected && (
                  <div className="mt-4 flex items-center gap-2 text-emerald-400 text-sm">
                    <Check size={16} />
                    Selected
                  </div>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Optional Subject */}
      <div className="mb-8">
        <label
          htmlFor="subject"
          className="block text-frost-dark-300 font-display text-sm uppercase tracking-wider mb-2"
        >
          Subject ID <span className="text-frost-dark-500">(Optional)</span>
        </label>
        <input
          id="subject"
          type="text"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          placeholder="user@example.com"
          className="input max-w-md"
        />
        <p className="text-frost-dark-500 text-sm mt-2">
          Used for tracking and leaderboard identification
        </p>
      </div>

      {/* Error Message */}
      {error && (
        <div className="mb-6 p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-red-400 font-medium">Spawn Failed</p>
            <p className="text-red-400/80 text-sm mt-1">{error}</p>
          </div>
        </div>
      )}

      {/* Spawn Button */}
      <div className="flex items-center gap-4">
        <button
          onClick={handleSpawn}
          disabled={!selectedTrack || loading}
          className="btn-primary inline-flex items-center gap-2"
        >
          {loading ? (
            <>
              <Loader2 className="w-5 h-5 animate-spin" />
              Spawning...
            </>
          ) : (
            <>
              <Zap size={18} />
              Spawn Scenario
              <ChevronRight size={18} />
            </>
          )}
        </button>
        {selectedTrack && !loading && (
          <p className="text-frost-dark-500 text-sm">
            Ready to spawn{" "}
            <span className="text-frost-dark-300">
              {tracks.find((t) => t.id === selectedTrack)?.name}
            </span>{" "}
            scenario
          </p>
        )}
      </div>

      {/* Info Cards */}
      <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="card p-6">
          <div className="w-10 h-10 rounded-lg bg-frost-blue-500/10 flex items-center justify-center mb-4">
            <Shield className="w-5 h-5 text-frost-blue-400" />
          </div>
          <h3 className="font-display font-semibold text-frost-dark-200 mb-2">
            Isolated Environment
          </h3>
          <p className="text-frost-dark-500 text-sm">
            Each scenario runs in a fully isolated network with deny-all egress by default
          </p>
        </div>
        <div className="card p-6">
          <div className="w-10 h-10 rounded-lg bg-frost-orange-500/10 flex items-center justify-center mb-4">
            <Zap className="w-5 h-5 text-frost-orange-400" />
          </div>
          <h3 className="font-display font-semibold text-frost-dark-200 mb-2">
            Deterministic Scoring
          </h3>
          <p className="text-frost-dark-500 text-sm">
            All completions are graded with reproducible criteria and signed verdicts
          </p>
        </div>
        <div className="card p-6">
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 flex items-center justify-center mb-4">
            <Lock className="w-5 h-5 text-emerald-400" />
          </div>
          <h3 className="font-display font-semibold text-frost-dark-200 mb-2">
            Audit Trail
          </h3>
          <p className="text-frost-dark-500 text-sm">
            Every action is logged with hash-chained evidence for compliance exports
          </p>
        </div>
      </div>
    </div>
  );
}
