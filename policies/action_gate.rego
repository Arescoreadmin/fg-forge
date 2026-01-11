package frostgate.forge.action

# Agent action validation policy
# Enforces action type restrictions, budget limits, and dangerous action blocking

default allow = false

# Allowed policy classes
policy_classes := {"read_only", "write", "execute", "network", "privileged"}

# Policy class budgets (cost units per action)
class_costs := {
    "read_only": 1,
    "write": 5,
    "execute": 10,
    "network": 15,
    "privileged": 50
}

# Default budget per scenario
default_budget := 1000

# Dangerous action patterns (blocked regardless of policy class)
dangerous_patterns := [
    "rm -rf /",
    "rm -rf /*",
    "dd if=/dev/zero",
    "mkfs",
    "> /dev/sda",
    ":(){ :|:& };:",
    "fork bomb",
    "chmod 777 /",
    "curl | sh",
    "wget | bash",
    "nc -e",
    "bash -i >&"
]

# Main allow rule
allow {
    valid_scenario
    valid_actor
    valid_action
    valid_policy_class
    budget_sufficient
    authorized
    not dangerous_action
}

# Validation helpers
valid_scenario {
    input.scenario_id != ""
    count(input.scenario_id) >= 4
}

valid_actor {
    input.actor != ""
    input.actor != "anonymous"
}

valid_action {
    input.action != ""
    count(input.action) <= 10000
}

valid_policy_class {
    input.policy_class != ""
    policy_classes[input.policy_class]
}

budget_sufficient {
    input.budget_ok == true
}

budget_sufficient {
    budget := object.get(input, "budget_remaining", default_budget)
    cost := class_costs[input.policy_class]
    budget >= cost
}

authorized {
    input.authorized == true
}

# Check for dangerous actions
dangerous_action {
    some pattern
    pattern := dangerous_patterns[_]
    contains(lower(input.action), lower(pattern))
}

# Check for shell injection patterns
dangerous_action {
    contains(input.action, "; rm")
}

dangerous_action {
    contains(input.action, "| rm")
}

dangerous_action {
    contains(input.action, "&& rm")
}

dangerous_action {
    contains(input.action, "`rm")
}

dangerous_action {
    contains(input.action, "$(rm")
}

# Calculate action cost
action_cost = cost {
    cost := class_costs[input.policy_class]
}

# Calculate remaining budget after action
remaining_budget = remaining {
    budget := object.get(input, "budget_remaining", default_budget)
    cost := class_costs[input.policy_class]
    remaining := budget - cost
}

# Deny reasons for debugging
deny_reasons[msg] {
    input.scenario_id == ""
    msg := "missing scenario_id"
}

deny_reasons[msg] {
    input.scenario_id != ""
    count(input.scenario_id) < 4
    msg := "scenario_id too short"
}

deny_reasons[msg] {
    input.actor == ""
    msg := "missing actor"
}

deny_reasons[msg] {
    input.actor == "anonymous"
    msg := "anonymous actors not allowed"
}

deny_reasons[msg] {
    input.action == ""
    msg := "missing action"
}

deny_reasons[msg] {
    input.action != ""
    count(input.action) > 10000
    msg := "action too long (maximum 10000 characters)"
}

deny_reasons[msg] {
    input.policy_class == ""
    msg := "missing policy_class"
}

deny_reasons[msg] {
    input.policy_class != ""
    not policy_classes[input.policy_class]
    msg := sprintf("invalid policy_class: %s (allowed: %v)", [input.policy_class, policy_classes])
}

deny_reasons[msg] {
    input.budget_ok != true
    budget := object.get(input, "budget_remaining", 0)
    cost := class_costs[input.policy_class]
    budget < cost
    msg := sprintf("budget exceeded: %d remaining, %d required for %s action", [budget, cost, input.policy_class])
}

deny_reasons[msg] {
    input.authorized != true
    msg := "action not authorized"
}

deny_reasons[msg] {
    dangerous_action
    msg := "action contains dangerous patterns"
}

# Action metadata for response
action_metadata := {
    "cost": action_cost,
    "remaining_budget": remaining_budget,
    "policy_class": input.policy_class
}
