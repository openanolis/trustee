package policy
import rego.v1

default allow := false

# This test resource contains fresh random bytes. The release runner replaces
# TEST_RESOURCE with the full path and restores the original policy afterwards.
allow if {
    data["resource-path"] == "TEST_RESOURCE"
    cpu := input.submods.cpu0
    cpu["ear.trustworthiness-vector"].hardware == 2
    q := cpu["ear.veraison.annotated-evidence"].tdx.quote
    q.header.tee_type == "81000000"
    q.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
    # TDATTRIBUTES is encoded in little-endian byte order. DEBUG is bit 0.
    regex.match("^[0-9a-f][02468ace][0-9a-f]{14}$", q.body.td_attributes)
}
