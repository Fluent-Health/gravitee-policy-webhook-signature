# Gravitee Policy Webhook Signature

A Gravitee APIM policy plugin that verifies HMAC-signed inbound webhooks at the gateway and rejects the request unless the signature matches — so a backend only ever sees deliveries that really came from the provider.

One policy covers the common signing schemes:

| Provider | `source` | Signature | Signed message |
| --- | --- | --- | --- |
| GitHub | `header` | `X-Hub-Signature-256: sha256=<hex>` | raw request body |
| Meta / WhatsApp Cloud API | `header` | `X-Hub-Signature-256: sha256=<hex>` | raw request body |
| Sentry integration platform | `header` | `Sentry-Hook-Signature: <hex>` | raw request body |
| Mailgun event webhooks | `mailgun-json` | `signature.signature` in the JSON body | `signature.timestamp + signature.token` |
| Mailgun routes (inbound mail) | `mailgun-multipart` | `signature` form field | `timestamp + token` form fields |

Anything else that signs the raw body with HMAC-SHA1/256/512 into a header, hex- or base64-encoded, fits `source: header`.

A project by [Fluent Health](https://github.com/Fluent-Health).

## Why a plugin rather than a script

These checks are often written as Groovy policies. That works, but it couples correctness to the gateway's Groovy sandbox whitelist: a constant-time comparison (`MessageDigest.isEqual`) or a harmless string helper that is not whitelisted turns into a `SecurityException`, and every delivery fails with a 500. Hand-written verifiers also tend to grow one guard at a time — an unguarded `split('=')[1]` or a null secret means junk input produces a 500 instead of a 401. A compiled policy has no sandbox, and every path here is tested.

## Behaviour

- **Fails closed, with a 4xx.** A missing, blank or malformed signature, a missing secret, and an unparseable body are all rejections. No input reaches the backend without a verified signature, and no input can throw its way to an unexplained 500.
- **Constant-time comparison** of the decoded digest bytes (`MessageDigest.isEqual`). Hex is therefore case-insensitive.
- **Raw bytes.** `header` sources HMAC the request body exactly as received — no charset decoding — and the body is forwarded untouched: the buffer that was verified is the buffer that is sent upstream. This matters for Mailgun routes, whose multipart bodies carry binary attachments that a decode/re-encode round trip would corrupt.
- **Secrets via Expression Language**, including deferred lookups such as `{#secrets.get('...')}` from a secret provider. Resolution goes through `TemplateEngine.eval`, the one entry point that resolves deferred values; the synchronous entry points would silently hand back the literal expression as the key.

## Compatibility

| Plugin | Requires APIM |
| --- | --- |
| 1.x | >= 4.12 |

Verified end to end by CI against APIM 4.12.0 and 4.12.20 (see `.github/workflows/integration-matrix.yml`).

## Configuration

The schema is deliberately flat and has **no defaults**: an API definition always states the whole contract.

| Property | Required | Description |
| --- | --- | --- |
| `source` | yes | `header`, `mailgun-json` or `mailgun-multipart` — see the table above. |
| `header` | when `source` is `header` | Header carrying the signature. |
| `prefix` | when `source` is `header` | Literal text before the digest, e.g. `sha256=`. Use `""` for a bare digest. |
| `algorithm` | yes | `HmacSHA1`, `HmacSHA256` or `HmacSHA512`. |
| `encoding` | yes | `hex` or `base64` — how the received digest is encoded. |
| `secret` | yes | The HMAC key. Supports Expression Language. |

The schema states these requirements (including the conditional one, as a draft-07 `if`/`then`), but **the management API does not validate policy configuration against it** — an incomplete configuration deploys without complaint. The policy therefore re-checks the whole configuration on every request and answers 500 (`WEBHOOK_SIGNATURE_MISCONFIGURED`) without reaching the backend if anything is missing.

### Examples (Gravitee Terraform provider)

GitHub:

```hcl
request = [{
  policy  = "webhook-signature"
  enabled = true
  configuration = jsonencode({
    source    = "header"
    header    = "X-Hub-Signature-256"
    prefix    = "sha256="
    algorithm = "HmacSHA256"
    encoding  = "hex"
    secret    = "{#secrets.get('/my-provider/github-webhook:secret')}"
  })
}]
```

Sentry — a bare hex digest, so the prefix is explicitly empty:

```hcl
configuration = jsonencode({
  source    = "header"
  header    = "Sentry-Hook-Signature"
  prefix    = ""
  algorithm = "HmacSHA256"
  encoding  = "hex"
  secret    = "{#secrets.get('/my-provider/sentry-app:client-secret')}"
})
```

Meta / WhatsApp: as GitHub, with the app secret as `secret`.

Mailgun event webhooks and routes — the signing key is Mailgun's *HTTP webhook signing key*:

```hcl
configuration = jsonencode({
  source    = "mailgun-json"        # or "mailgun-multipart" for routes
  algorithm = "HmacSHA256"
  encoding  = "hex"
  secret    = "{#secrets.get('/my-provider/mailgun:webhook-signing-key')}"
})
```

## Failures

Every rejection carries a stable key. To change the status or body a sender sees, add a [response template](https://documentation.gravitee.io/apim/create-apis/response-templates) for the key rather than configuring the policy.

| Key | Status | When |
| --- | --- | --- |
| `WEBHOOK_SIGNATURE_MISSING` | 401 (400 for `mailgun-multipart`) | No signature: header absent or blank, or Mailgun signature fields missing. |
| `WEBHOOK_SIGNATURE_MALFORMED` | 401 | The header does not hold the configured prefix followed by a digest. |
| `WEBHOOK_SIGNATURE_INVALID` | 401 | The signature does not match, or is not a well-formed digest. |
| `WEBHOOK_SIGNATURE_SECRET_UNAVAILABLE` | 401 | `secret` resolved to nothing — e.g. a secret not populated yet. |
| `WEBHOOK_SIGNATURE_BODY_INVALID` | 400 | `mailgun-json`: the body is not JSON. `mailgun-multipart`: the body is not `multipart/form-data` with a boundary. |
| `WEBHOOK_SIGNATURE_SECRET_UNRESOLVED` | 500 | Evaluating `secret` failed, e.g. the secret provider errored. |
| `WEBHOOK_SIGNATURE_MISCONFIGURED` | 500 | The policy configuration is incomplete or invalid. |
| `WEBHOOK_SIGNATURE_ERROR` | 500 | An unexpected failure — a bug, not a sender error. |

## Limitations

- **Mailgun's scheme does not sign the body**, only `timestamp + token`. A captured valid triple therefore authenticates any body. Mailgun recommends rejecting stale timestamps and reused tokens; this policy does neither yet.
- No replay protection for any provider: the providers above do not put a timestamp inside the signed message (GitHub, Meta) or put it in a separate header (Sentry).

## Development

Prerequisites: Java 21, Maven, Docker, Terraform 1.15.1 (for the end-to-end test).

```bash
mvn test     # unit tests
mvn verify   # unit tests + the container-backed end-to-end test
```

Test fixtures live in `src/test/resources/fixtures`. Their expected signatures were computed independently of the policy (Python's `hmac`), and GitHub's published test vector is included as an external anchor.
