package frostgate.forge.spawn

# Spawn request validation policy
# Validates request structure, tracks, tenant authorization, and rate limits
#
# Input contract (recommended):
# {
#   "request_id": string,
#   "track": string,
#   "billing_ok": bool,
#   "tenant_blocked": bool,
#   "rate_limit_exceeded": bool,
#   "scenarios_used": number
# }

default allow := false

# ----------------------------
# Config
# ----------------------------

allowed_tracks := {"netplus", "ccna", "cissp"}

track_tiers := {
	"netplus": "basic",
	"ccna": "standard",
	"cissp": "premium",
}

tier_quotas := {
	"basic": 20,
	"standard": 10,
	"premium": 5,
}

# ----------------------------
# Normalized inputs (defensive)
# ----------------------------

req_id := object.get(input, "request_id", "")

track := object.get(input, "track", "")

billing_ok := object.get(input, "billing_ok", false)

tenant_blocked := object.get(input, "tenant_blocked", false)

rate_limit_exceeded := object.get(input, "rate_limit_exceeded", false)

raw_scenarios_used := object.get(input, "scenarios_used", 0)

# scenarios_used should be a non-negative number; default 0 (safe)
scenarios_used := used if {
	is_number(raw_scenarios_used)
	raw_scenarios_used >= 0
	used := raw_scenarios_used
} else := 0

# ----------------------------
# Main allow rule (ALL gates)
# ----------------------------

allow if {
	valid_request_id
	valid_track
	billing_authorized
	not tenant_blocked
	not rate_limit_exceeded
	within_quota
	count(deny_reasons) == 0
}

# ----------------------------
# Validation helpers
# ----------------------------

valid_request_id if {
	is_string(req_id)
	req_id != ""
	count(req_id) >= 8
	count(req_id) <= 64
}

valid_track if {
	is_string(track)
	track != ""
	allowed_tracks[track]
}

billing_authorized if {
	billing_ok == true
}

valid_scenarios_used if {
	is_number(raw_scenarios_used)
	raw_scenarios_used >= 0
} else if {
	# allow absent scenarios_used (defaults to 0); treat only invalid types/negative as invalid
	not object.get(input, "scenarios_used", null)
}

# ----------------------------
# Quotas
# ----------------------------

quota_for_track(t) := quota if {
	tier := track_tiers[t]
	quota := tier_quotas[tier]
}

quota_for_track_safe(t) := quota if {
	quota := quota_for_track(t)
} else := 0

within_quota if {
	quota := quota_for_track(track)
	scenarios_used < quota
}

remaining_quota := remaining if {
	quota := quota_for_track(track)
	remaining := max([quota - scenarios_used, 0])
} else := 0

# ----------------------------
# Deny reasons (deterministic)
# ----------------------------

# NOTE: This is designed for operators/devs. Don’t expose all of it to end users in prod.

deny_reasons contains "missing request_id" if {
	req_id == ""
}

deny_reasons contains "request_id must be a string" if {
	req_id != ""
	not is_string(req_id)
}

deny_reasons contains "request_id too short (minimum 8 characters)" if {
	is_string(req_id)
	req_id != ""
	count(req_id) < 8
}

deny_reasons contains "request_id too long (maximum 64 characters)" if {
	is_string(req_id)
	req_id != ""
	count(req_id) > 64
}

deny_reasons contains "missing track" if {
	track == ""
}

# Split the invalid expression into two rules (valid Rego + clearer ops signal)
deny_reasons contains "track must be a string" if {
	track != ""
	not is_string(track)
}

deny_reasons contains msg if {
	is_string(track)
	track != ""
	not allowed_tracks[track]
	msg := sprintf("unsupported track: %v (allowed: %v)", [track, allowed_tracks])
}

deny_reasons contains "billing not authorized" if {
	billing_ok != true
}

deny_reasons contains "tenant is blocked" if {
	tenant_blocked == true
}

deny_reasons contains "rate limit exceeded - please wait before spawning more scenarios" if {
	rate_limit_exceeded == true
}

deny_reasons contains "scenarios_used must be a non-negative number" if {
	object.get(input, "scenarios_used", null)
	not valid_scenarios_used
}

deny_reasons contains msg if {
	valid_track
	quota := quota_for_track(track)
	scenarios_used >= quota
	msg := sprintf("quota exceeded: %d/%d scenarios used for track %s", [scenarios_used, quota, track])
}

# ----------------------------
# Response metadata (safe)
# ----------------------------

# Always defined (even for invalid track) so logs/clients don't get undefined surprises.
spawn_metadata := {
	"track": track,
	"track_tier": object.get(track_tiers, track, "unknown"),
	"quota_limit": quota_for_track_safe(track),
	"scenarios_used": scenarios_used,
	"remaining_quota": remaining_quota,
	"billing_ok": billing_ok,
	"tenant_blocked": tenant_blocked,
	"rate_limit_exceeded": rate_limit_exceeded,
}
