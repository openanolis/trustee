# Resource Policy (Default)
# -------------------------
#
# This default KBS resource policy decides whether a requester is allowed to
# access a resource based on the Attestation Claims (input) and the resource
# path (data). It is tailored for EAR tokens:
#
# - Resource path (data):
#   {
#     "resource-path": "<REPO>/<TYPE>/<TAG>"
#   }
#   The path is a string with three segments, e.g. "repo/key/prod".
#
# - Attestation Claims (input):
#   When using EAR tokens, the trustworthiness vector is expected under:
#     input.submods["cpu0"]["ear.trustworthiness-vector"]
#   where the trust vector contains (at least):
#     configuration, executables, file_system, hardware
#
# Default decision:
#   Allow only when cpu0 reports trusted levels for ALL the four dimensions
#   according to the current policy threshold (<= 32 by default):
#     configuration, executables, file_system, hardware.
#   Otherwise deny.
#
# Note:
# - If cpu0 is not present in the EAR claims, the request is denied.
# - You can further extend this file by adding platform recognizers based on
#   annotated-evidence (e.g. input.submods["cpu0"]["ear.veraison.annotated-evidence"].tdx)
#   or by adding per-repository rules.

package policy

import rego.v1

default allow = false

# ---------------------------
# Resource path helpers
# ---------------------------
resource_path := data["resource-path"]
path_parts := split(resource_path, "/")

is_repo(name) if { count(path_parts) == 3; path_parts[0] == name }
is_type(t)    if { count(path_parts) == 3; path_parts[1] == t }
is_tag(tag)   if { count(path_parts) == 3; path_parts[2] == tag }

# ---------------------------
# EAR helpers (cpu0-only)
# ---------------------------

# All four core dimensions must satisfy the trust threshold (<= 32)
core4_strict(tv) if {
	tv["configuration"] <= 32
	tv["executables"] <= 32
	tv["file-system"] <= 32
	tv["hardware"] <= 32
}

# ---------------------------
# Default decision
# ---------------------------

allow if {
	# cpu0 must exist
	s := input.submods["cpu0"]
	# cpu0 must carry a trustworthiness vector
	tv := s["ear.trustworthiness-vector"]
	# and it must satisfy the strict condition
	core4_strict(tv)
}
