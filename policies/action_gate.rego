package frostgate.forge.action

default allow = false

allow {
  input.scenario_id != ""
  input.actor != ""
  input.action != ""
  input.policy_class != ""
  input.budget_ok == true
  input.authorized == true
}

deny_reasons[msg] {
  input.scenario_id == ""
  msg := "missing scenario_id"
}

deny_reasons[msg] {
  input.actor == ""
  msg := "missing actor"
}

deny_reasons[msg] {
  input.action == ""
  msg := "missing action"
}

deny_reasons[msg] {
  input.policy_class == ""
  msg := "missing policy_class"
}

deny_reasons[msg] {
  input.budget_ok != true
  msg := "budget exceeded"
}

deny_reasons[msg] {
  input.authorized != true
  msg := "action not authorized"
}
