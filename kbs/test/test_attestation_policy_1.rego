package test_policy_1

default allow = false

allow {
    input["submods"]["cpu"]["ear.veraison.annotated-evidence"]["sample"]
}

allow {
    input["submods"]["cpu"]["ear.veraison.annotated-evidence"]["tdx"]
} 