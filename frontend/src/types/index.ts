// FrostGate Forge API Types

export type Track = "netplus" | "ccna" | "cissp";

export type Tier = "free" | "basic" | "standard" | "premium" | "enterprise";

export type ScenarioStatus =
  | "pending"
  | "creating"
  | "running"
  | "completed"
  | "completed_with_errors"
  | "failed"
  | "timeout";

// Spawn Request/Response
export interface SpawnRequest {
  track: Track;
  subject?: string;
  tenant_id?: string;
}

export interface SpawnResponse {
  request_id: string;
  scenario_id: string;
  access_url: string;
  access_token: string;
  expires_at: string;
  sat: string;
}

// Scenario State
export interface ScenarioState {
  scenario_id: string;
  request_id: string;
  track: Track;
  subject: string | null;
  tenant_id: string | null;
  tier: Tier | null;
  status: ScenarioStatus;
  network_id: string | null;
  containers: string[];
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  completion_reason: string | null;
  error: string | null;
}

// Score Types
export interface ScoreCriterion {
  criterion_id: string;
  passed: boolean;
  weight: number;
  weighted_score: number;
}

export interface ScoreResult {
  scenario_id: string;
  track: Track;
  score: number;
  passed: number;
  total: number;
  criteria: ScoreCriterion[];
  computed_at: string;
}

// Leaderboard
export interface LeaderboardEntry {
  rank: number;
  scenario_id: string;
  subject?: string;
  score: number;
  passed: number;
  total: number;
  completed_at: string;
}

// Stats
export interface AggregateStats {
  total_scenarios: number;
  completed_scenarios: number;
  average_score: number;
  scores_by_track: Record<Track, number>;
}

// API Error
export interface ApiError {
  detail: string;
  status_code?: number;
}

// Health Check
export interface HealthStatus {
  status: "healthy" | "degraded" | "unhealthy";
  checks?: Record<string, boolean>;
}
