package policy

import rego.v1

default allow = false

allow if {
    input["tee"] == "sample"
}

allow if {
    input["tee"] == "snp"
    input["evidence"] != ""
} 