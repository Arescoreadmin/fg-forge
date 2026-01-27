package frostgate.forge.training

import rego.v1

# -----------------------------------------------------------------------------
# training_gate.rego (Rego v1, deterministic, hardened)
# -----------------------------------------------------------------------------
# Goals:
# - Never 500: all access is type-guarded.
# - Deterministic extraction: track/tier are single-valued via else-chains.
# - Accepts: template:"netplus" and/or metadata.labels=["class:netplus","tier:foundation"]
# - Baseline security: require network.egress == "deny"
# - Exposes: allow (bool) and decision (object) for orchestrator.
# -----------------------------------------------------------------------------

default allow := false

default decision := {"allow": false, "reason": "denied", "track": "unknown", "tier": "unknown"}

allowed_tracks := {"netplus"}

# NOTE: you currently have plan:"TEAM" + tier:foundation label in your example.
# If that pairing is intentionally allowed, keep "foundation".
allowed_tiers := {"team", "foundation"}

# -----------------------------------------------------------------------------
# Helpers (all type-safe)
# -----------------------------------------------------------------------------

safe_lower(x) := y if {
	is_string(x)
	y := lower(x)
} else := y if {
	y := "unknown"
}

trim_prefix(s, p) := out if {
	is_string(s)
	is_string(p)
	startswith(s, p)
	out := substring(s, count(p), -1)
} else := out if {
	out := s
}

# Deterministic label lookup: returns the FIRST (lowest index) match only.
label_value(labels, prefix) := val if {
	is_array(labels)
	is_string(prefix)

	idxs := [i |
		some i
		lbl := labels[i]
		is_string(lbl)
		startswith(lbl, prefix)
	]

	count(idxs) > 0
	m := min(idxs)
	lbl := labels[m]
	val := trim_prefix(lbl, prefix)
}

egress := e if {
	is_object(input.network)
	is_string(input.network.egress)
	e := input.network.egress
} else := e if {
	e := "unknown"
}

# -----------------------------------------------------------------------------
# Deterministic track extraction (single-valued)
# -----------------------------------------------------------------------------

track := t if {
	is_string(input.track)
	t := input.track
} else := t if {
	is_string(input.template)
	t := input.template
} else := t if {
	is_string(input.template_id)
	t := input.template_id
} else := t if {
	is_object(input.details)
	is_string(input.details.track)
	t := input.details.track
} else := t if {
	is_object(input.metadata)
	is_object(input.metadata.labels)
	is_string(input.metadata.labels.track)
	t := input.metadata.labels.track
} else := t if {
	is_object(input.metadata)
	v := label_value(input.metadata.labels, "class:")
	is_string(v)
	t := v
} else := t if {
	is_object(input.metadata)
	v := label_value(input.metadata.labels, "track:")
	is_string(v)
	t := v
} else := t if {
	is_object(input.metadata)
	is_string(input.metadata.name)
	startswith(input.metadata.name, "netplus-")
	t := "netplus"
} else := t if {
	is_object(input.sat)
	is_string(input.sat.track)
	t := input.sat.track
} else := t if {
	is_object(input.claims)
	is_string(input.claims.track)
	t := input.claims.track
} else := t if {
	t := "unknown"
}

track_lc := safe_lower(track)

# -----------------------------------------------------------------------------
# Deterministic tier extraction (single-valued)
# -----------------------------------------------------------------------------

tier := x if {
	is_string(input.tier)
	x := lower(input.tier)
} else := x if {
	# orchestrator sends plan:"TEAM"
	is_string(input.plan)
	x := lower(input.plan)
} else := x if {
	is_object(input.sat)
	is_string(input.sat.tier)
	x := lower(input.sat.tier)
} else := x if {
	is_object(input.claims)
	is_string(input.claims.tier)
	x := lower(input.claims.tier)
} else := x if {
	is_object(input.metadata)
	v := label_value(input.metadata.labels, "tier:")
	is_string(v)
	x := lower(v)
} else := x if {
	x := "unknown"
}

# -----------------------------------------------------------------------------
# Policy
# -----------------------------------------------------------------------------

allow if {
	allowed_tracks[track_lc]
	allowed_tiers[tier]
	egress == "deny"
}

reason := "allowed" if allow

reason := "denied" if not allow

decision := {
	"allow": allow,
	"reason": reason,
	"track": track_lc,
	"tier": tier,
}
