# RESTful AS error responses

RESTful AS errors use [Problem Details for HTTP APIs (RFC 9457)](https://www.rfc-editor.org/rfc/rfc9457)
with the media type `application/problem+json`. Successful responses are
unchanged.

Clients should branch on `code` and use the HTTP status as a fallback. The
human-readable `detail` can change and must not be parsed. The full source error
chain is logged by RESTful AS and is not returned to clients. RESTful AS does
not synthesize a request or correlation identifier; clients should use their
own tracing context when one is required.

```json
{
  "type": "https://github.com/confidential-containers/attestation-service/errors/BadRequest",
  "title": "Invalid evidence encoding",
  "status": 400,
  "code": "AS.EVIDENCE.INVALID_ENCODING",
  "detail": "An evidence field uses an invalid encoding.",
  "retryable": false,
  "field": "verification_requests[0].evidence.quote"
}
```

## Error codes

| Code | HTTP | Retryable | Meaning |
| --- | ---: | :---: | --- |
| `AS.REQUEST.INVALID_JSON` | 400 | no | The HTTP body is invalid JSON or does not match the endpoint schema. |
| `AS.REQUEST.INVALID_ARGUMENT` | 400 | no | A request argument is missing or invalid. |
| `AS.REQUEST.UNSUPPORTED_TEE` | 400 | no | The TEE is unknown or its verifier is not enabled. |
| `AS.CHALLENGE.INVALID_TOKEN` | 401 | no | The challenge token is invalid or expired. |
| `AS.EVIDENCE.INVALID_FORMAT` | 400 | no | Decoded evidence has an invalid JSON structure or field type. |
| `AS.EVIDENCE.INVALID_ENCODING` | 400 | no | Evidence, quote, event log, runtime data, or init data uses an invalid encoding. |
| `AS.EVIDENCE.INVALID_QUOTE` | 422 | no | A decoded quote has an invalid length, structure, version, or algorithm. |
| `AS.EVIDENCE.VERIFICATION_FAILED` | 422 | no | Evidence signature or quote verification failed. |
| `AS.EVIDENCE.BINDING_MISMATCH` | 422 | no | Evidence is not bound to the expected report data, init data, or event log. |
| `AS.DEPENDENCY.BAD_RESPONSE` | 502 | yes | An attestation dependency returned an invalid response. |
| `AS.DEPENDENCY.UNAVAILABLE` | 503 | yes | An attestation dependency is temporarily unavailable. |
| `AS.INTERNAL.ERROR` | 500 | no | An unclassified internal, configuration, or I/O error occurred. |

The first typed verifier implementation covers TDX. Verifiers that have not yet
been migrated safely fall back to `AS.INTERNAL.ERROR`; RESTful AS does not infer
error categories from display strings.

## Nested TDX evidence encoding

TDX requests contain two encoding layers:

| Field | Encoding |
| --- | --- |
| `verification_requests[i].evidence` | RFC 4648 Base64URL without padding |
| decoded TDX Evidence JSON `.quote` | RFC 4648 standard Base64 |
| decoded TDX Evidence JSON `.cc_eventlog` | RFC 4648 standard Base64 |

The decoders are intentionally strict. In particular, `_` is valid in
Base64URL but not in the standard Base64 used by the inner `quote` and
`cc_eventlog` fields.
