# Agent guidance — gravitee-policy-webhook-signature

## Verification rule (non-negotiable)

**Never claim the policy works, is fixed, refactored, or "verified" until `E2EGatewayIT` has passed in this working tree.** `mvn test` alone is insufficient — it exercises mocks. The authoritative check runs Gravitee APIM (management + gateway), MongoDB and WireMock as real containers and configures the API through the official Terraform provider.

```bash
mvn verify
```

Do **not** use `-DskipTests=true` with `verify` — Maven reads that as "skip failsafe too", and the IT is silently skipped (failsafe logs `Tests are skipped`). If you see that line, you have NOT verified anything. To skip only the unit tests:

```bash
mvn verify -Dtest='!*' -Dsurefire.failIfNoSpecifiedTests=false
```

### Prerequisites

- Docker daemon running (`docker info` succeeds).
- `terraform` 1.15.1 (the IT writes a `.tool-versions` pinning it into each working directory).
- Network access to pull `mongo:7.0`, `wiremock/wiremock:3.5.4` and `graviteeio/apim-{management-api,gateway}` for the version under test.

If container startup fails with `all predefined address pools have been fully subnetted`, the Docker daemon is out of network subnets — usually idle networks left behind by earlier runs. That is an environment problem, not a test result.

### What "passed" looks like

Failsafe reports `Tests run: 7, Failures: 0, Errors: 0, Skipped: 0` for `E2EGatewayIT`, and the build ends with `BUILD SUCCESS`.

### When the IT cannot run

If Docker is genuinely unavailable, **say so explicitly** rather than claiming success. Do not silently fall back to "unit tests pass".

## Version matrix

`E2EGatewayIT` takes the APIM version from `-Dapim.version` (default: the newest verified release). CI runs it across the matrix in `.github/workflows/integration-matrix.yml`, a reusable workflow shared by `ci.yml` and `release.yml` so the two cannot drift. Every leg is pinned, never the floating `latest` tag.

The gateway API versions in `pom.xml` are `provided` and must track the target APIM line. Read them off the image rather than guessing:

```bash
docker run --rm --entrypoint sh graviteeio/apim-gateway:4.12.20 \
  -c 'ls /opt/graviteeio-gateway/lib /opt/graviteeio-gateway/lib/ext' \
  | grep -iE 'gravitee-(gateway-api|policy-api|common|expression)'
```

The policy resolves the secret only through `TemplateEngine.eval(String, Class)`, whose descriptor is the same in the EL version gateway-api pulls at compile time and the one APIM 4.12 ships. Re-check after any APIM bump:

```bash
javap -c -p -cp target/classes io.fluenthealth.gravitee.policy.webhooksignature.WebhookSignaturePolicy \
  | grep -oE '(InterfaceMethod|Method) io/gravitee/el/[^ ]*' | sort -u
```

## Architecture notes

- **V4 reactive only.** The policy implements `HttpPolicy` and does its work in `onRequest` through `request().onBody(...)`. There is no V2 code path.
- **The body is forwarded as the same `Buffer` object that was verified.** Never rebuild it — in particular never through a `String`. Mailgun route bodies carry binary attachments, and a decode/re-encode round trip replaces every non-UTF-8 byte with `EF BF BD`, silently corrupting the document while the request still succeeds. The unit tests assert identity (`isSameAs`) and the IT asserts the backend received identical bytes.
- **HMAC over raw bytes.** `header` sources sign the body as received. Do not convert to a `String` first.
- **Secret resolution goes through `TemplateEngine.eval` only.** The synchronous entry points (`getValue`, `convert`, `evalNow`) do not resolve deferred values such as `{#secrets.get(...)}` and return the literal expression without error — which would then become the HMAC key.
- **No defaults, anywhere.** Configuration fields start null, `gravitee.json` declares no `default`, and `SchemaTest` enforces both. A missing value is a 500 `WEBHOOK_SIGNATURE_MISCONFIGURED`, checked per request rather than at construction, so a bad config fails its own flow rather than the API deployment. That check is the only enforcement: the management API does **not** validate policy configuration against `gravitee.json` (measured — a config missing even a top-level `required` property applies cleanly), so never rely on the schema to keep a bad config out.
- **Every rejection is a `Rejection` with a stable key**; anything else reaching `toFailure` is a bug and is logged at ERROR as `WEBHOOK_SIGNATURE_ERROR`. Status codes for Mailgun deliberately differ by source (a missing field is 400 for routes, 401 for event webhooks), matching the verifiers this plugin was written to replace.
- `Multipart` reads only plain form fields, views the body as ISO-8859-1 (one char per byte, so binary parts cannot throw or shift offsets), skips file parts, and lets the first occurrence of a repeated name win.

## Test fixtures

`src/test/resources/fixtures` holds one realistic delivery per provider. Expected signatures in the tests were computed **outside Java** (Python `hmac`) over those exact bytes, so a bug in the policy's HMAC code cannot make the tests agree with it. If you add or change a fixture, recompute its signature the same way — never by running the policy.

## Repo conventions

- Java 21, Maven, Mockito with `LENIENT` strictness for the policy tests.
- Tests use AssertJ; WireMock as the backend and Testcontainers for the E2E.
- This is a public repository: no internal hostnames, ticket references or real secrets in code, fixtures, commits or PR descriptions.
