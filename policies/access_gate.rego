package foundry.access

default allow := false

known_caps := {"web_tty"}

deny_reasons contains "capability_missing" if capability_missing

deny_reasons contains "capability_unknown" if not cap_known

deny_reasons contains "token_exp_missing" if token_exp_missing

deny_reasons contains "token_expired" if token_expired

deny_reasons contains "tenant_blocked" if tenant_blocked

deny_reasons contains "track_not_allowed" if track_not_allowed

has_deny if {
	some r
	deny_reasons[r]
}

allow if not has_deny

capability_missing if not input.capability

capability_missing if input.capability == ""

cap_known if known_caps[input.capability]

token_exp_missing if not input.token_exp

token_expired if {
	not token_exp_missing
	input.token_exp <= time.now_ns() / 1000000000
}

tenant_blocked if input.tenant_blocked == true

track_not_allowed if {
	input.track_allowlist_enabled == true
	not track_allowed
}

track_allowed if {
	input.track_allowlist[input.track] == true
}
