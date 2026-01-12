package frostgate.forge.llm

# LLM proposal governance policy
# Validates proposals, signatures, canary checks, and risk levels

default allow := false

# Policy classes and their risk levels
policy_class_risk := {
	"read_only": "low",
	"write": "medium",
	"execute": "high",
	"network": "high",
	"privileged": "critical",
}

# Canary requirements by risk level
canary_required := {
	"low": false,
	"medium": true,
	"high": true,
	"critical": true,
}

# Signature requirements by risk level
signature_required := {
	"low": false,
	"medium": true,
	"high": true,
	"critical": true,
}

# Main allow rule
allow if {
	valid_proposal_id
	valid_scenario_id
	signature_check_passed
	canary_check_passed
	valid_policy_class
	authorized
}

# Validation helpers
valid_proposal_id if {
	input.proposal_id != ""
	count(input.proposal_id) >= 8
}

valid_scenario_id if {
	input.scenario_id != ""
	count(input.scenario_id) >= 4
}

signature_check_passed if {
	# Get risk level for policy class
	risk := policy_class_risk[input.policy_class]

	# Check if signature is required
	not signature_required[risk]
}

signature_check_passed if {
	risk := policy_class_risk[input.policy_class]
	signature_required[risk]
	input.signed == true
}

canary_check_passed if {
	risk := policy_class_risk[input.policy_class]
	not canary_required[risk]
}

canary_check_passed if {
	risk := policy_class_risk[input.policy_class]
	canary_required[risk]
	input.canary == true
}

valid_policy_class if {
	input.policy_class != ""
	policy_class_risk[input.policy_class]
}

authorized if {
	input.authorized == true
}

# Get risk level for a proposal
risk_level := level if {
	level := policy_class_risk[input.policy_class]
}

# Check if proposal requires human review
requires_human_review if {
	risk_level == "critical"
}

requires_human_review if {
	input.policy_class == "privileged"
}

# Deny reasons for debugging
deny_reasons contains msg if {
	input.proposal_id == ""
	msg := "missing proposal_id"
}

deny_reasons contains msg if {
	input.proposal_id != ""
	count(input.proposal_id) < 8
	msg := "proposal_id too short (minimum 8 characters)"
}

deny_reasons contains msg if {
	input.scenario_id == ""
	msg := "missing scenario_id"
}

deny_reasons contains msg if {
	input.scenario_id != ""
	count(input.scenario_id) < 4
	msg := "scenario_id too short"
}

deny_reasons contains msg if {
	risk := policy_class_risk[input.policy_class]
	signature_required[risk]
	input.signed != true
	msg := sprintf("signature required for %s risk actions", [risk])
}

deny_reasons contains msg if {
	risk := policy_class_risk[input.policy_class]
	canary_required[risk]
	input.canary != true
	msg := sprintf("canary execution required for %s risk actions", [risk])
}

deny_reasons contains msg if {
	input.policy_class == ""
	msg := "missing policy_class"
}

deny_reasons contains msg if {
	input.policy_class != ""
	not policy_class_risk[input.policy_class]
	msg := sprintf("invalid policy_class: %s", [input.policy_class])
}

deny_reasons contains msg if {
	input.authorized != true
	msg := "proposal not authorized"
}

# Proposal metadata for response
proposal_metadata := {
	"risk_level": risk_level,
	"requires_signature": signature_required[risk_level],
	"requires_canary": canary_required[risk_level],
	"requires_human_review": requires_human_review,
}
