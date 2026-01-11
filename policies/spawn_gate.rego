package frostgate.forge.spawn

default allow = false

allowed_tracks := {"netplus", "ccna", "cissp"}

allow {
  input.request_id != ""
  input.track != ""
  input.track == allowed_tracks[_]
  input.billing_ok == true
}

deny_reasons[msg] {
  input.request_id == ""
  msg := "missing request_id"
}

deny_reasons[msg] {
  input.track == ""
  msg := "missing track"
}

deny_reasons[msg] {
  input.track != ""
  not allowed_tracks[input.track]
  msg := sprintf("unsupported track: %s", [input.track])
}

deny_reasons[msg] {
  input.billing_ok != true
  msg := "billing not authorized"
}
