package policy

import rego.v1

default allow = true

# This is a more permissive policy for testing
allow if {
    true
} 