package foundry.access_test

import data.foundry.access

now := time.now_ns() / 1000000000

base_input := {
	"request_id": "req-1",
	"tenant_id": "t1",
	"subject": "u1",
	"scenario_id": "scn-abc",
	"track": "netplus",
	"capability": "web_tty",
	"source_ip": "1.2.3.4",
	"user_agent": "test",
	"token_exp": now + 60,
	"tenant_blocked": false,
	"track_allowlist_enabled": false,
	"track_allowlist": {"netplus": true},
}

patched(p) := object.union(base_input, p)

test_allow_happy_path if {
	access.allow with input as base_input
	not access.has_deny with input as base_input
}

test_deny_unknown_capability if {
	i := patched({"capability": "nope"})
	not access.allow with input as i
	access.has_deny with input as i
	"capability_unknown" == access.deny_reasons[_] with input as i
}

test_deny_missing_capability_field if {
	object.remove(base_input, {"capability"}, i)
	not access.allow with input as i
	access.has_deny with input as i
	"capability_missing" == access.deny_reasons[_] with input as i
}

test_deny_empty_capability if {
	i := patched({"capability": ""})
	not access.allow with input as i
	access.has_deny with input as i
	"capability_missing" == access.deny_reasons[_] with input as i
}

test_deny_missing_token_exp if {
	object.remove(base_input, {"token_exp"}, i)
	not access.allow with input as i
	access.has_deny with input as i
	"token_exp_missing" == access.deny_reasons[_] with input as i
}

test_deny_expired_token if {
	i := patched({"token_exp": now - 1})
	not access.allow with input as i
	access.has_deny with input as i
	"token_expired" == access.deny_reasons[_] with input as i
}

test_deny_tenant_blocked if {
	i := patched({"tenant_blocked": true})
	not access.allow with input as i
	access.has_deny with input as i
	"tenant_blocked" == access.deny_reasons[_] with input as i
}

test_track_allowlist_enabled_denies_when_missing_allowlist_map if {
	object.remove(base_input, {"track_allowlist"}, i)
	j := object.union(i, {"track_allowlist_enabled": true})
	not access.allow with input as j
	access.has_deny with input as j
	"track_not_allowed" == access.deny_reasons[_] with input as j
}

test_track_allowlist_enabled_denies_when_track_not_in_allowlist if {
	object.remove(base_input, {"track_allowlist"}, b)
	i := object.union(b, {"track_allowlist_enabled": true, "track_allowlist": {"ccna": true}})
	not access.allow with input as i
	access.has_deny with input as i
	"track_not_allowed" == access.deny_reasons[_] with input as i
}

test_track_allowlist_enabled_allows_when_present if {
	i := patched({"track_allowlist_enabled": true, "track_allowlist": {"netplus": true}})
	access.allow with input as i
	not access.has_deny with input as i
}
