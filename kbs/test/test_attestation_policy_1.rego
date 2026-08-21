package test_policy_1

import rego.v1

default allow = false

allow if {
    input["submods"]["cpu"]["ear.veraison.annotated-evidence"]["sample"]
}

allow if {
    input["submods"]["cpu"]["ear.veraison.annotated-evidence"]["tdx"]
}
