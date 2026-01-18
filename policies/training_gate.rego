package frostgate.forge.training

# Training scenario validation policy
# Enforces resource limits, security constraints, and track-specific rules

default allow := false

# Track configurations
track_configs := {
	"netplus": {
		"max_cpu": 2,
		"max_memory_mb": 1024,
		"max_containers": 3,
		"attacker_max_exploits": 0,
		"egress_allowed": false,
		"privileged_allowed": false,
	},
	"ccna": {
		"max_cpu": 4,
		"max_memory_mb": 2048,
		"max_containers": 5,
		"attacker_max_exploits": 0,
		"egress_allowed": false,
		"privileged_allowed": false,
	},
	"cissp": {
		"max_cpu": 8,
		"max_memory_mb": 4096,
		"max_containers": 10,
		"attacker_max_exploits": 5,
		"egress_allowed": false,
		"privileged_allowed": true,
	},
}

# Get track from labels
get_track(labels) := track if {
	some i
	label := labels[i]
	startswith(label, "class:")
	track := substring(label, 6, -1)
}

# Main allow rule
allow if {
	track := get_track(input.metadata.labels)
	config := track_configs[track]

	# Resource limits
	input.limits.cpu <= config.max_cpu
	input.limits.memory_mb <= config.max_memory_mb
	input.limits.attacker_max_exploits <= config.attacker_max_exploits

	# Container count
	count(input.assets.containers) <= config.max_containers

	# Network egress
	not config.egress_allowed
	input.network.egress == "deny"

	# All containers must be read-only unless privileged allowed
	all_containers_safe(input.assets.containers, config.privileged_allowed)
}

# Alternative allow for egress-allowed tracks
allow if {
	track := get_track(input.metadata.labels)
	config := track_configs[track]
	config.egress_allowed

	input.limits.cpu <= config.max_cpu
	input.limits.memory_mb <= config.max_memory_mb
	input.limits.attacker_max_exploits <= config.attacker_max_exploits
	count(input.assets.containers) <= config.max_containers
	all_containers_safe(input.assets.containers, config.privileged_allowed)
}

# Helper: Check all containers are safe
all_containers_safe(containers, privileged_allowed) if {
	count([c | c := containers[_]; not container_safe(c, privileged_allowed)]) == 0
}

container_safe(container, _) if {
	# Read-only filesystem required
	container.read_only == true
}

container_safe(container, privileged_allowed) if {
	# Or privileged is allowed and explicitly set
	privileged_allowed
	container.privileged == true
}

# Deny reasons for debugging
deny_reasons contains msg if {
	track := get_track(input.metadata.labels)
	not track_configs[track]
	msg := sprintf("unsupported track: %s", [track])
}

deny_reasons contains msg if {
	track := get_track(input.metadata.labels)
	config := track_configs[track]
	input.limits.cpu > config.max_cpu
	msg := sprintf("CPU limit %d exceeds maximum %d for track %s", [input.limits.cpu, config.max_cpu, track])
}

deny_reasons contains msg if {
	track := get_track(input.metadata.labels)
	config := track_configs[track]
	input.limits.memory_mb > config.max_memory_mb
	msg := sprintf("memory limit %d MB exceeds maximum %d MB for track %s", [input.limits.memory_mb, config.max_memory_mb, track])
}

deny_reasons contains msg if {
	track := get_track(input.metadata.labels)
	config := track_configs[track]
	input.limits.attacker_max_exploits > config.attacker_max_exploits
	msg := sprintf("attacker exploits %d exceeds maximum %d for track %s", [input.limits.attacker_max_exploits, config.attacker_max_exploits, track])
}

deny_reasons contains msg if {
	track := get_track(input.metadata.labels)
	config := track_configs[track]
	count(input.assets.containers) > config.max_containers
	msg := sprintf("container count %d exceeds maximum %d for track %s", [count(input.assets.containers), config.max_containers, track])
}

deny_reasons contains msg if {
	track := get_track(input.metadata.labels)
	config := track_configs[track]
	not config.egress_allowed
	input.network.egress != "deny"
	msg := sprintf("egress must be 'deny' for track %s", [track])
}

deny_reasons contains msg if {
	some i
	container := input.assets.containers[i]
	container.read_only != true
	track := get_track(input.metadata.labels)
	config := track_configs[track]
	not config.privileged_allowed
	msg := sprintf("container '%s' must have read_only=true", [container.name])
}

# -----------------------------------------------------------------------------
# Allow contract
# -----------------------------------------------------------------------------
# If nothing is explicitly denied, allow the request.
# This prevents "deny_reasons == [] but allow == false" footguns.
allow if {
	count(deny_reasons) == 0
}
