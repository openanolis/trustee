package policy
import rego.v1

# An administrator must explicitly authorize resource release for an appraised client.
default allow := false
