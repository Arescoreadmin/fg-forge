package frostgate.forge.llm

default allow = false

allow {
  input.proposal_id != ""
  input.scenario_id != ""
  input.signed == true
  input.canary == true
  input.policy_class != ""
  input.authorized == true
}

deny_reasons[msg] {
  input.proposal_id == ""
  msg := "missing proposal_id"
}

deny_reasons[msg] {
  input.scenario_id == ""
  msg := "missing scenario_id"
}

deny_reasons[msg] {
  input.signed != true
  msg := "proposal not signed"
}

deny_reasons[msg] {
  input.canary != true
  msg := "proposal not canaried"
}

deny_reasons[msg] {
  input.policy_class == ""
  msg := "missing policy_class"
}

deny_reasons[msg] {
  input.authorized != true
  msg := "proposal not authorized"
}
