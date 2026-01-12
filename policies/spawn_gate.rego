package frostgate.forge.spawn

# Spawn request validation policy
# Validates request structure, tracks, tenant authorization, and rate limits

default allow = false

# Allowed tracks
allowed_tracks := {"netplus", "ccna", "cissp"}

# Track tiers (determines quota multiplier)
track_tiers := {
    "netplus": "basic",
    "ccna": "standard",
    "cissp": "premium"
}

# Tier quotas (scenarios per 24h window)
tier_quotas := {
    "basic": 20,
    "standard": 10,
    "premium": 5
}

# Main allow rule
allow if {
    valid_request_id
    valid_track
    billing_authorized
    tenant_not_blocked
    within_rate_limit
}

# Validation helpers
valid_request_id if {
    input.request_id != ""
    count(input.request_id) >= 8
    count(input.request_id) <= 64
}

valid_track if {
    input.track != ""
    allowed_tracks[input.track]
}

billing_authorized if {
    input.billing_ok == true
}

tenant_not_blocked if {
    not input.tenant_blocked
}

tenant_not_blocked if {
    input.tenant_blocked == false
}

within_rate_limit if {
    not input.rate_limit_exceeded
}

within_rate_limit if {
    input.rate_limit_exceeded == false
}

# Quota calculation
quota_for_track(track) = quota if {
    tier := track_tiers[track]
    quota := tier_quotas[tier]
}

remaining_quota = remaining if {
    quota := quota_for_track(input.track)
    used := object.get(input, "scenarios_used", 0)
    remaining := quota - used
}

# Deny reasons for debugging
deny_reasons contains msg if {
    input.request_id == ""
    msg := "missing request_id"
}

deny_reasons contains msg if {
    input.request_id != ""
    count(input.request_id) < 8
    msg := "request_id too short (minimum 8 characters)"
}

deny_reasons contains msg if {
    input.request_id != ""
    count(input.request_id) > 64
    msg := "request_id too long (maximum 64 characters)"
}

deny_reasons contains msg if {
    input.track == ""
    msg := "missing track"
}

deny_reasons contains msg if {
    input.track != ""
    not allowed_tracks[input.track]
    msg := sprintf("unsupported track: %s (allowed: %v)", [input.track, allowed_tracks])
}

deny_reasons contains msg if {
    input.billing_ok != true
    msg := "billing not authorized"
}

deny_reasons contains msg if {
    input.tenant_blocked == true
    msg := "tenant is blocked"
}

deny_reasons contains msg if {
    input.rate_limit_exceeded == true
    msg := "rate limit exceeded - please wait before spawning more scenarios"
}

deny_reasons contains msg if {
    quota := quota_for_track(input.track)
    used := object.get(input, "scenarios_used", 0)
    used >= quota
    msg := sprintf("quota exceeded: %d/%d scenarios used for track %s", [used, quota, input.track])
}

# Additional metadata for response
spawn_metadata := {
    "track_tier": track_tiers[input.track],
    "quota_limit": quota_for_track(input.track),
    "remaining_quota": remaining_quota
}
