package test_policy_2

default allow = false

allow {
    input["submods"]["cpu"]["ear.veraison.annotated-evidence"]["sample"]
}

allow {
    input["submods"]["cpu"]["ear.veraison.annotated-evidence"]["sgx"]
} 