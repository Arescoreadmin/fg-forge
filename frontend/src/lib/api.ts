import type {
  SpawnRequest,
  SpawnResponse,
  ScenarioState,
  ScoreResult,
  LeaderboardEntry,
  AggregateStats,
  Track,
  ApiError,
} from "@/types";

const API_BASE = "/api";

class ApiClient {
  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${API_BASE}${endpoint}`;

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...((options.headers as Record<string, string>) || {}),
    };

    // Add request ID for tracing
    headers["x-request-id"] = crypto.randomUUID();

    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error: ApiError = await response.json().catch(() => ({
        detail: `HTTP ${response.status}: ${response.statusText}`,
      }));
      throw new Error(error.detail || "An error occurred");
    }

    return response.json();
  }

  // ============================================
  // Spawn Service
  // ============================================

  async spawn(request: SpawnRequest): Promise<SpawnResponse> {
    return this.request<SpawnResponse>("/spawn", {
      method: "POST",
      body: JSON.stringify(request),
    });
  }

  async getAccess(scenarioId: string, token: string): Promise<ScenarioState> {
    return this.request<ScenarioState>(`/access/${scenarioId}?token=${token}`);
  }

  // ============================================
  // Orchestrator
  // ============================================

  async listScenarios(): Promise<ScenarioState[]> {
    return this.request<ScenarioState[]>("/scenarios");
  }

  async getScenario(scenarioId: string): Promise<ScenarioState> {
    return this.request<ScenarioState>(`/scenarios/${scenarioId}`);
  }

  async deleteScenario(scenarioId: string): Promise<void> {
    await this.request(`/scenarios/${scenarioId}`, {
      method: "DELETE",
    });
  }

  // ============================================
  // Scoreboard
  // ============================================

  async getScore(scenarioId: string): Promise<ScoreResult> {
    return this.request<ScoreResult>(`/scores/${scenarioId}`);
  }

  async listScores(): Promise<ScoreResult[]> {
    return this.request<ScoreResult[]>("/scores");
  }

  async getLeaderboard(track: Track): Promise<LeaderboardEntry[]> {
    return this.request<LeaderboardEntry[]>(`/leaderboard/${track}`);
  }

  async getStats(): Promise<AggregateStats> {
    return this.request<AggregateStats>("/stats");
  }
}

// Export singleton instance
export const api = new ApiClient();

// Export types for convenience
export type { SpawnRequest, SpawnResponse, ScenarioState, ScoreResult };
