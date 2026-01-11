package frostgate.forge.training

default allow = false

allow {
  input.metadata.labels[_] == "class:netplus"
  input.limits.attacker_max_exploits <= 0
  input.network.egress == "deny"
}

allow {
  input.metadata.labels[_] == "class:ccna"
  input.limits.attacker_max_exploits <= 0
  input.network.egress == "deny"
}

allow {
  input.metadata.labels[_] == "class:cissp"
  input.limits.attacker_max_exploits <= 5
  input.network.egress == "deny"
}
