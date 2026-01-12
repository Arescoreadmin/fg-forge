package frostgate.forge.quota

# Quota enforcement policy
# Validates tenant quotas, rate limits, and fairness constraints

default allow := false

# Default quotas per tier
tier_quotas := {
	"free": {
		"max_scenarios_per_day": 5,
		"max_concurrent": 1,
		"max_cpu_per_scenario": 1,
		"max_memory_mb_per_scenario": 512,
		"rate_limit_per_minute": 2,
	},
	"basic": {
		"max_scenarios_per_day": 20,
		"max_concurrent": 2,
		"max_cpu_per_scenario": 2,
		"max_memory_mb_per_scenario": 1024,
		"rate_limit_per_minute": 5,
	},
	"standard": {
		"max_scenarios_per_day": 50,
		"max_concurrent": 5,
		"max_cpu_per_scenario": 4,
		"max_memory_mb_per_scenario": 2048,
		"rate_limit_per_minute": 10,
	},
	"premium": {
		"max_scenarios_per_day": 200,
		"max_concurrent": 10,
		"max_cpu_per_scenario": 8,
		"max_memory_mb_per_scenario": 8192,
		"rate_limit_per_minute": 30,
	},
	"enterprise": {
		"max_scenarios_per_day": 1000,
		"max_concurrent": 50,
		"max_cpu_per_scenario": 16,
		"max_memory_mb_per_scenario": 16384,
		"rate_limit_per_minute": 100,
	},
}

# Main allow rule
allow if {
	valid_tenant
	not tenant_blocked
	within_daily_quota
	within_concurrent_limit
	within_rate_limit
	within_resource_limits
}

# Validation helpers
valid_tenant if {
	input.tenant_id != ""
}

tenant_blocked if {
	input.blocked == true
}

# Get quota config for tenant tier
get_quota_config(tier) := config if {
	config := tier_quotas[tier]
}

get_quota_config(tier) := config if {
	not tier_quotas[tier]
	config := tier_quotas.free
}

# Daily quota check
within_daily_quota if {
	tier := object.get(input, "tier", "free")
	config := get_quota_config(tier)
	scenarios_today := object.get(input, "scenarios_today", 0)
	scenarios_today < config.max_scenarios_per_day
}

# Concurrent scenario limit
within_concurrent_limit if {
	tier := object.get(input, "tier", "free")
	config := get_quota_config(tier)
	active_scenarios := object.get(input, "active_scenarios", 0)
	active_scenarios < config.max_concurrent
}

# Rate limit check
within_rate_limit if {
	tier := object.get(input, "tier", "free")
	config := get_quota_config(tier)
	requests_per_minute := object.get(input, "requests_per_minute", 0)
	requests_per_minute < config.rate_limit_per_minute
}

# Resource limits check
within_resource_limits if {
	tier := object.get(input, "tier", "free")
	config := get_quota_config(tier)
	requested_cpu := object.get(input, "requested_cpu", 1)
	requested_memory := object.get(input, "requested_memory_mb", 512)
	requested_cpu <= config.max_cpu_per_scenario
	requested_memory <= config.max_memory_mb_per_scenario
}

# Calculate remaining quota
# Deny reasons
deny_reasons contains msg if {
	input.tenant_id == ""
	msg := "missing tenant_id"
}

deny_reasons contains msg if {
	input.blocked == true
	msg := "tenant is blocked"
}

deny_reasons contains msg if {
	tier := object.get(input, "tier", "free")
	config := get_quota_config(tier)
	scenarios_today := object.get(input, "scenarios_today", 0)
	scenarios_today >= config.max_scenarios_per_day
	msg := sprintf("daily quota exceeded: %d/%d scenarios", [scenarios_today, config.max_scenarios_per_day])
}

deny_reasons contains msg if {
	tier := object.get(input, "tier", "free")
	config := get_quota_config(tier)
	active_scenarios := object.get(input, "active_scenarios", 0)
	active_scenarios >= config.max_concurrent
	msg := sprintf("concurrent limit reached: %d/%d active scenarios", [active_scenarios, config.max_concurrent])
}

deny_reasons contains msg if {
	tier := object.get(input, "tier", "free")
	config := get_quota_config(tier)
	requests_per_minute := object.get(input, "requests_per_minute", 0)
	requests_per_minute >= config.rate_limit_per_minute
	msg := sprintf("rate limit exceeded: %d/%d requests per minute", [requests_per_minute, config.rate_limit_per_minute])
}

deny_reasons contains msg if {
	tier := object.get(input, "tier", "free")
	config := get_quota_config(tier)
	requested_cpu := object.get(input, "requested_cpu", 0)
	requested_cpu > config.max_cpu_per_scenario
	msg := sprintf("CPU request %d exceeds limit %d for tier %s", [requested_cpu, config.max_cpu_per_scenario, tier])
}

deny_reasons contains msg if {
	tier := object.get(input, "tier", "free")
	config := get_quota_config(tier)
	requested_memory := object.get(input, "requested_memory_mb", 0)
	requested_memory > config.max_memory_mb_per_scenario
	msg := sprintf("memory request %d MB exceeds limit %d MB for tier %s", [requested_memory, config.max_memory_mb_per_scenario, tier])
}

# Quota metadata for response
quota_metadata := {
	"tier": object.get(input, "tier", "free"),
	"daily_remaining": remaining_daily_quota(),
	"concurrent_remaining": remaining_concurrent_slots(),
	"limits": get_quota_config(object.get(input, "tier", "free")),
}

# Calculate remaining quota (v1-safe functions)
remaining_daily_quota := remaining if {
	tier := object.get(input, "tier", "free")
	config := get_quota_config(tier)
	scenarios_today := object.get(input, "scenarios_today", 0)
	remaining := config.max_scenarios_per_day - scenarios_today
}

remaining_concurrent_slots := remaining if {
	tier := object.get(input, "tier", "free")
	config := get_quota_config(tier)
	active_scenarios := object.get(input, "active_scenarios", 0)
	remaining := config.max_concurrent - active_scenarios
}
