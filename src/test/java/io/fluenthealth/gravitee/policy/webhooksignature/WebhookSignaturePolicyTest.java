package io.fluenthealth.gravitee.policy.webhooksignature;

import static io.fluenthealth.gravitee.policy.webhooksignature.WebhookSignaturePolicy.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import io.fluenthealth.gravitee.policy.webhooksignature.configuration.WebhookSignaturePolicyConfiguration;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainRequest;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.core.MaybeTransformer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * One nested class per signature dialect the policy replaces. Every expected signature below was
 * computed outside Java (Python's {@code hmac}) over the fixture files in
 * {@code src/test/resources/fixtures}, so a mistake in the policy's own HMAC code cannot make its
 * tests agree with it.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class WebhookSignaturePolicyTest {

    @Mock
    HttpPlainExecutionContext ctx;

    @Mock
    HttpPlainRequest request;

    @Mock
    TemplateEngine templateEngine;

    HttpHeaders headers;
    WebhookSignaturePolicyConfiguration configuration;

    @BeforeEach
    void setUp() {
        headers = HttpHeaders.create();
        configuration = new WebhookSignaturePolicyConfiguration();
        when(ctx.request()).thenReturn(request);
        when(request.headers()).thenReturn(headers);
        when(ctx.getTemplateEngine()).thenReturn(templateEngine);
        // eval, not getValue: only eval resolves a deferred value. Identity by default.
        when(templateEngine.<String>eval(any(String.class), eq(String.class))).thenAnswer(inv -> Maybe.just(inv.getArgument(0)));
    }

    // ── GitHub: X-Hub-Signature-256: sha256=<hex HMAC-SHA256 of raw body> ───

    @Nested
    class GitHub {

        static final String SECRET = "gh-webhook-test-secret";
        static final String SIGNATURE = "sha256=c7021dee67411a38556d99fddb58023f2ec25f8509a664d0bc49fb9a6a23ff35";

        @BeforeEach
        void configure() {
            header("X-Hub-Signature-256", "sha256=", "HmacSHA256", "hex", SECRET);
        }

        @Test
        void acceptsGitHubsPublishedTestVector() {
            // https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#testing-the-webhook-payload-validation
            configuration.setSecret("It's a Secret to Everybody");
            headers.set("X-Hub-Signature-256", "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17");

            assertPassed(run("Hello, World!".getBytes(StandardCharsets.UTF_8)));
        }

        @Test
        void acceptsAValidDeliveryAndForwardsTheBodyUntouched() {
            headers.set("X-Hub-Signature-256", SIGNATURE);
            var body = fixture("github-ping.json");

            var outcome = run(body);

            assertPassed(outcome);
            assertThat(outcome.forwarded().getBytes()).isEqualTo(body);
        }

        @Test
        void acceptsUppercaseHex() {
            headers.set("X-Hub-Signature-256", "sha256=" + SIGNATURE.substring(7).toUpperCase());
            assertPassed(run(fixture("github-ping.json")));
        }

        @Test
        void verifiesTheFirstValueWhenTheHeaderRepeats() {
            headers.add("X-Hub-Signature-256", SIGNATURE);
            headers.add("X-Hub-Signature-256", "sha256=00");
            assertPassed(run(fixture("github-ping.json")));
        }

        @Test
        void rejectsATamperedBody() {
            headers.set("X-Hub-Signature-256", SIGNATURE);
            var body = fixture("github-ping.json");
            body[body.length - 2] ^= 1;

            assertRejected(run(body), 401, KEY_INVALID);
        }

        @Test
        void rejectsTheWrongSecret() {
            headers.set("X-Hub-Signature-256", SIGNATURE);
            configuration.setSecret("not-the-secret");
            assertRejected(run(fixture("github-ping.json")), 401, KEY_INVALID);
        }

        @Test
        void rejectsAMissingHeader() {
            assertRejected(run(fixture("github-ping.json")), 401, KEY_MISSING);
        }

        @Test
        void rejectsABlankHeader() {
            headers.set("X-Hub-Signature-256", "  ");
            assertRejected(run(fixture("github-ping.json")), 401, KEY_MISSING);
        }

        // The Groovy verifier's `split('=')[1]` threw on these, turning junk input into a 500.
        @ParameterizedTest
        @ValueSource(strings = { "sha256=", "sha256", "c7021dee67411a38556d99fddb58023f", "sha1=57b8ae149fce1cffdf1e64e6ac0ee51c5d9f2026", "=" })
        void rejectsAMalformedHeaderWith401(String value) {
            headers.set("X-Hub-Signature-256", value);
            assertRejected(run(fixture("github-ping.json")), 401, KEY_MALFORMED);
        }

        @ParameterizedTest
        @ValueSource(strings = { "sha256=not-hex", "sha256=abc", "sha256=c7021dee67411a38556d99fddb58023f2ec25f8509a664d0bc49fb9a6a23ff3500" })
        void rejectsADigestThatDoesNotDecodeOrHasTheWrongLength(String value) {
            headers.set("X-Hub-Signature-256", value);
            assertRejected(run(fixture("github-ping.json")), 401, KEY_INVALID);
        }

        @Test
        void rejectsARequestWithNoBodyRatherThanFailing() {
            headers.set("X-Hub-Signature-256", SIGNATURE);
            var outcome = run(null);
            assertRejected(outcome, 401, KEY_INVALID);
        }

        @Test
        void acceptsAnEmptyBodyThatIsGenuinelySigned() {
            // HMAC-SHA256("gh-webhook-test-secret", "")
            headers.set("X-Hub-Signature-256", "sha256=" + Vectors.EMPTY_BODY_GITHUB);
            var outcome = run(null);
            assertThat(outcome.failure()).isNull();
            assertThat(outcome.completed()).isTrue();
        }
    }

    // ── Sentry: Sentry-Hook-Signature: <bare hex HMAC-SHA256 of raw body> ────

    @Nested
    class Sentry {

        static final String SIGNATURE = "fb4b88679d0640b79c2c217477b076c14b7f00c38f7784cfdfe237f4da9cb288";

        @BeforeEach
        void configure() {
            header("Sentry-Hook-Signature", "", "HmacSHA256", "hex", "sentry-client-secret-test");
        }

        @Test
        void acceptsAValidDelivery() {
            headers.set("Sentry-Hook-Signature", SIGNATURE);
            assertPassed(run(fixture("sentry-issue-alert.json")));
        }

        @Test
        void rejectsAPrefixedSignatureWhenNoPrefixIsConfigured() {
            headers.set("Sentry-Hook-Signature", "sha256=" + SIGNATURE);
            assertRejected(run(fixture("sentry-issue-alert.json")), 401, KEY_INVALID);
        }

        @Test
        void rejectsAMissingHeader() {
            assertRejected(run(fixture("sentry-issue-alert.json")), 401, KEY_MISSING);
        }

        @Test
        void rejectsAnInvalidSignature() {
            headers.set("Sentry-Hook-Signature", SIGNATURE.replace('f', 'e'));
            assertRejected(run(fixture("sentry-issue-alert.json")), 401, KEY_INVALID);
        }
    }

    // ── Meta / WhatsApp: X-Hub-Signature-256: sha256=<hex>, over raw UTF-8 ──

    @Nested
    class WhatsApp {

        static final String SIGNATURE = "sha256=c7d384a436d05098567e881029919f93c0d554763953433b7453aa8ef63d5b4c";

        @BeforeEach
        void configure() {
            header("X-Hub-Signature-256", "sha256=", "HmacSHA256", "hex", "meta-app-secret-test");
        }

        @Test
        void acceptsAValidDeliveryWithNonAsciiText() {
            headers.set("X-Hub-Signature-256", SIGNATURE);
            var body = fixture("whatsapp-message.json");
            assertThat(new String(body, StandardCharsets.UTF_8)).contains("नमस्ते 👋 café");

            var outcome = run(body);

            assertPassed(outcome);
            assertThat(outcome.forwarded().getBytes()).isEqualTo(body);
        }

        // The Groovy WhatsApp verifiers had neither guard: both of these were 500s.
        @Test
        void rejectsAHeaderWithNoPrefixWith401() {
            headers.set("X-Hub-Signature-256", "deadbeef");
            assertRejected(run(fixture("whatsapp-message.json")), 401, KEY_MALFORMED);
        }

        @Test
        void rejectsAnUnresolvedSecretWith401() {
            headers.set("X-Hub-Signature-256", SIGNATURE);
            secretResolvesTo(Maybe.empty());
            assertRejected(run(fixture("whatsapp-message.json")), 401, KEY_SECRET_UNAVAILABLE);
        }
    }

    // ── Mailgun event webhooks: JSON body, HMAC(timestamp + token) ───────────

    @Nested
    class MailgunWebhook {

        @BeforeEach
        void configure() {
            mailgun(WebhookSignaturePolicyConfiguration.SOURCE_MAILGUN_JSON);
        }

        @Test
        void acceptsAValidEventAndForwardsTheBodyUntouched() {
            var body = fixture("mailgun-event.json");
            var outcome = run(body);
            assertPassed(outcome);
            assertThat(outcome.forwarded().getBytes()).isEqualTo(body);
        }

        @Test
        void acceptsANumericTimestamp() {
            var body = json(
                "{\"signature\":{\"timestamp\":1749416383,\"token\":\"%s\",\"signature\":\"%s\"}}",
                Vectors.MAILGUN_TOKEN,
                Vectors.MAILGUN_SIGNATURE
            );
            assertPassed(run(body));
        }

        @Test
        void rejectsAForgedSignature() {
            var body = json(
                "{\"signature\":{\"timestamp\":\"1749416384\",\"token\":\"%s\",\"signature\":\"%s\"}}",
                Vectors.MAILGUN_TOKEN,
                Vectors.MAILGUN_SIGNATURE
            );
            assertRejected(run(body), 401, KEY_INVALID);
        }

        @ParameterizedTest
        @ValueSource(
            strings = {
                "{}",
                "[]",
                "{\"signature\":null}",
                "{\"signature\":\"x\"}",
                "{\"signature\":{\"timestamp\":\"1\",\"token\":\"t\"}}",
                "{\"signature\":{\"timestamp\":\"1\",\"token\":\"t\",\"signature\":\"\"}}",
                "{\"signature\":{\"timestamp\":{},\"token\":\"t\",\"signature\":\"aa\"}}",
                "{\"signature\":{\"timestamp\":null,\"token\":\"t\",\"signature\":\"aa\"}}",
            }
        )
        void rejectsMissingSignatureFieldsWith401(String body) {
            assertRejected(run(body.getBytes(StandardCharsets.UTF_8)), 401, KEY_MISSING);
        }

        @ParameterizedTest
        @ValueSource(strings = { "not json", "{\"signature\":", "" })
        void rejectsABodyThatIsNotJsonWith400(String body) {
            assertRejected(run(body.getBytes(StandardCharsets.UTF_8)), 400, KEY_BODY_INVALID);
        }

        @Test
        void rejectsARequestWithNoBodyWith400() {
            assertRejected(run(null), 400, KEY_BODY_INVALID);
        }

        // The Groovy Mailgun verifiers NPE'd here (500).
        @Test
        void rejectsAnUnresolvedSecretWith401() {
            secretResolvesTo(Maybe.just(""));
            assertRejected(run(fixture("mailgun-event.json")), 401, KEY_SECRET_UNAVAILABLE);
        }
    }

    // ── Mailgun routes: multipart/form-data, HMAC(timestamp + token) ─────────

    @Nested
    class MailgunRoute {

        static final String CONTENT_TYPE = "multipart/form-data; boundary=" + Vectors.BOUNDARY;

        @BeforeEach
        void configure() {
            mailgun(WebhookSignaturePolicyConfiguration.SOURCE_MAILGUN_MULTIPART);
        }

        @Test
        void acceptsAValidRouteAndForwardsTheBinaryAttachmentByteForByte() {
            headers.set("Content-Type", CONTENT_TYPE);
            var body = fixture("mailgun-route.multipart");

            var outcome = run(body);

            assertPassed(outcome);
            // The same buffer object, not a re-encoded copy: a String round trip turns every
            // non-UTF-8 byte of an attachment into EF BF BD and silently corrupts the document.
            assertThat(outcome.forwarded()).isSameAs(outcome.received());
            assertThat(outcome.forwarded().getBytes()).isEqualTo(body);
        }

        @ParameterizedTest
        @ValueSource(
            strings = {
                "multipart/form-data; boundary=\"" + Vectors.BOUNDARY + "\"",
                "Multipart/Form-Data;boundary=" + Vectors.BOUNDARY,
                "multipart/form-data; charset=utf-8; boundary=" + Vectors.BOUNDARY,
            }
        )
        void acceptsContentTypeVariants(String contentType) {
            headers.set("Content-Type", contentType);
            assertPassed(run(fixture("mailgun-route.multipart")));
        }

        @ParameterizedTest
        @ValueSource(strings = { "application/json", "application/x-www-form-urlencoded", "multipart/form-data", "multipart/mixed; boundary=x" })
        void rejectsANonMultipartBodyWith400(String contentType) {
            headers.set("Content-Type", contentType);
            assertRejected(run(fixture("mailgun-route.multipart")), 400, KEY_BODY_INVALID);
        }

        @Test
        void rejectsAMissingContentTypeWith400() {
            assertRejected(run(fixture("mailgun-route.multipart")), 400, KEY_BODY_INVALID);
        }

        @Test
        void rejectsMissingSignatureFieldsWith400() {
            headers.set("Content-Type", CONTENT_TYPE);
            var body = new String(fixture("mailgun-route.multipart"), StandardCharsets.ISO_8859_1)
                .replace("name=\"signature\"", "name=\"not-the-signature\"")
                .getBytes(StandardCharsets.ISO_8859_1);
            assertRejected(run(body), 400, KEY_MISSING);
        }

        @Test
        void rejectsAForgedSignature() {
            headers.set("Content-Type", CONTENT_TYPE);
            var body = new String(fixture("mailgun-route.multipart"), StandardCharsets.ISO_8859_1)
                .replace(Vectors.MAILGUN_TOKEN, Vectors.MAILGUN_TOKEN.replace('a', 'b'))
                .getBytes(StandardCharsets.ISO_8859_1);
            assertRejected(run(body), 401, KEY_INVALID);
        }
    }

    // ── Algorithms and encodings beyond the five live dialects ───────────────

    @Nested
    class Algorithms {

        @Test
        void hmacSha1Hex() {
            header("X-Hub-Signature", "sha1=", "HmacSHA1", "hex", "gh-webhook-test-secret");
            headers.set("X-Hub-Signature", "sha1=57b8ae149fce1cffdf1e64e6ac0ee51c5d9f2026");
            assertPassed(run(fixture("github-ping.json")));
        }

        @Test
        void hmacSha512Base64() {
            header("X-Signature", "", "HmacSHA512", "base64", "gh-webhook-test-secret");
            headers.set("X-Signature", "eNi+A8AvjlvmXZsCQc5dlYc6sD39p7LbCoZkkm53KsGvIF93GjkX5hK2Xc6fAs7ih2VonSIXKbNadR9HPRDhXg==");
            assertPassed(run(fixture("github-ping.json")));
        }

        @Test
        void base64ThatDoesNotDecodeIsInvalid() {
            header("X-Signature", "", "HmacSHA512", "base64", "gh-webhook-test-secret");
            headers.set("X-Signature", "!!!");
            assertRejected(run(fixture("github-ping.json")), 401, KEY_INVALID);
        }
    }

    // ── Secret resolution ────────────────────────────────────────────────────

    @Nested
    class Secret {

        @BeforeEach
        void configure() {
            header("X-Hub-Signature-256", "sha256=", "HmacSHA256", "hex", "{#secrets.get('/provider/webhook:secret')}");
            headers.set("X-Hub-Signature-256", GitHub.SIGNATURE);
        }

        @Test
        void resolvesADeferredSecretAsynchronously() {
            secretResolvesTo(Maybe.just(GitHub.SECRET).delay(20, TimeUnit.MILLISECONDS));
            assertPassed(run(fixture("github-ping.json")));
        }

        @Test
        void neverUsesTheUnresolvedExpressionAsTheKey() {
            // An engine that hands the expression back unresolved must not verify anything.
            assertRejected(run(fixture("github-ping.json")), 401, KEY_INVALID);
        }

        @Test
        void aSecretThatResolvesToNothingIs401() {
            secretResolvesTo(Maybe.empty());
            assertRejected(run(fixture("github-ping.json")), 401, KEY_SECRET_UNAVAILABLE);
        }

        @Test
        void aSecretProviderFailureIs500() {
            secretResolvesTo(Maybe.error(new IllegalStateException("secret provider down")));
            assertRejected(run(fixture("github-ping.json")), 500, KEY_SECRET_UNRESOLVED);
        }

        @Test
        void anEngineThatThrowsIs500() {
            when(templateEngine.<String>eval(any(String.class), eq(String.class))).thenThrow(new IllegalArgumentException("bad expression"));
            assertRejected(run(fixture("github-ping.json")), 500, KEY_SECRET_UNRESOLVED);
        }

        @Test
        void theSignatureIsCheckedBeforeTheSecretIsResolved() {
            headers.remove("X-Hub-Signature-256");
            secretResolvesTo(Maybe.error(new IllegalStateException("must not be called")));
            assertRejected(run(fixture("github-ping.json")), 401, KEY_MISSING);
        }
    }

    // ── Configuration: no defaults, fail closed ──────────────────────────────

    @Nested
    class Configuration {

        @BeforeEach
        void configure() {
            header("X-Hub-Signature-256", "sha256=", "HmacSHA256", "hex", GitHub.SECRET);
            headers.set("X-Hub-Signature-256", GitHub.SIGNATURE);
        }

        @Test
        void aCompleteConfigurationPasses() {
            assertPassed(run(fixture("github-ping.json")));
        }

        @Test
        void startsOutEmpty() {
            var fresh = new WebhookSignaturePolicyConfiguration();
            assertThat(fresh.getSource()).isNull();
            assertThat(fresh.getHeader()).isNull();
            assertThat(fresh.getPrefix()).isNull();
            assertThat(fresh.getAlgorithm()).isNull();
            assertThat(fresh.getEncoding()).isNull();
            assertThat(fresh.getSecret()).isNull();
        }

        @Test
        void missingSource() {
            assertMisconfigured(c -> c.setSource(null));
        }

        @Test
        void unknownSource() {
            assertMisconfigured(c -> c.setSource("body"));
        }

        @Test
        void missingAlgorithm() {
            assertMisconfigured(c -> c.setAlgorithm(null));
        }

        @Test
        void unsupportedAlgorithm() {
            assertMisconfigured(c -> c.setAlgorithm("HmacMD5"));
        }

        @Test
        void missingEncoding() {
            assertMisconfigured(c -> c.setEncoding(null));
        }

        @Test
        void missingSecret() {
            assertMisconfigured(c -> c.setSecret(null));
        }

        @Test
        void missingHeaderForHeaderSource() {
            assertMisconfigured(c -> c.setHeader(null));
        }

        @Test
        void missingPrefixForHeaderSource() {
            assertMisconfigured(c -> c.setPrefix(null));
        }

        @Test
        void headerAndPrefixAreNotNeededForMailgun() {
            mailgun(WebhookSignaturePolicyConfiguration.SOURCE_MAILGUN_JSON);
            assertThat(configuration.getHeader()).isNull();
            assertPassed(run(fixture("mailgun-event.json")));
        }

        private void assertMisconfigured(Consumer<WebhookSignaturePolicyConfiguration> breakIt) {
            breakIt.accept(configuration);
            assertRejected(run(fixture("github-ping.json")), 500, KEY_MISCONFIGURED);
        }
    }

    // ── Harness ──────────────────────────────────────────────────────────────

    /** Values shared with the fixture generator. */
    static final class Vectors {

        static final String BOUNDARY = "----MailgunBoundary7MA4YWxkTrZu0gW";
        static final String MAILGUN_KEY = "mailgun-signing-key-test";
        static final String MAILGUN_TOKEN = "a8ce0edb2dd8301dee6c2405235584e45aa91d1e9f979f3de0";
        static final String MAILGUN_SIGNATURE = "36815bffa9a4fa3c79f099854df1497b651fa6c73eb787efb08b79620186eef3";
        static final String EMPTY_BODY_GITHUB = "cdc2fd20c6dbbbfe408ddbf774f02af53bc965c8b459f6da5eb6e2bfe20f8f2b";
    }

    record Outcome(Buffer received, Buffer forwarded, ExecutionFailure failure, boolean completed) {}

    private void header(String header, String prefix, String algorithm, String encoding, String secret) {
        configuration.setSource(WebhookSignaturePolicyConfiguration.SOURCE_HEADER);
        configuration.setHeader(header);
        configuration.setPrefix(prefix);
        configuration.setAlgorithm(algorithm);
        configuration.setEncoding(encoding);
        configuration.setSecret(secret);
    }

    private void mailgun(String source) {
        configuration.setSource(source);
        configuration.setHeader(null);
        configuration.setPrefix(null);
        configuration.setAlgorithm("HmacSHA256");
        configuration.setEncoding("hex");
        configuration.setSecret(Vectors.MAILGUN_KEY);
    }

    private void secretResolvesTo(Maybe<String> resolution) {
        when(templateEngine.<String>eval(any(String.class), eq(String.class))).thenReturn(resolution);
    }

    /**
     * Drives {@code onRequest} the way the gateway does: the policy registers a body transformer,
     * the gateway applies it to the buffered body, and an interruption surfaces as an error.
     */
    private Outcome run(byte[] body) {
        var received = body == null ? null : Buffer.buffer(body);
        var forwarded = new AtomicReference<Buffer>();
        var failure = new AtomicReference<ExecutionFailure>();

        when(request.onBody(any())).thenAnswer(inv -> {
            MaybeTransformer<Buffer, Buffer> transformer = inv.getArgument(0);
            var upstream = received == null ? Maybe.<Buffer>empty() : Maybe.just(received);
            return Maybe.wrap(transformer.apply(upstream)).doOnSuccess(forwarded::set).ignoreElement();
        });
        when(ctx.interruptBodyWith(any(ExecutionFailure.class))).thenAnswer(inv -> {
            failure.set(inv.getArgument(0));
            return Maybe.error(new IllegalStateException("interrupted"));
        });

        boolean completed;
        try {
            new WebhookSignaturePolicy(configuration).onRequest(ctx).timeout(5, TimeUnit.SECONDS).blockingAwait();
            completed = true;
        } catch (RuntimeException e) {
            completed = false;
        }
        return new Outcome(received, forwarded.get(), failure.get(), completed);
    }

    private static void assertPassed(Outcome outcome) {
        assertThat(outcome.failure()).as("interruption").isNull();
        assertThat(outcome.completed()).as("completed without error").isTrue();
        if (outcome.received() != null) {
            assertThat(outcome.forwarded()).as("forwarded body").isSameAs(outcome.received());
        }
    }

    private static void assertRejected(Outcome outcome, int status, String key) {
        assertThat(outcome.failure()).as("interruption").isNotNull();
        assertThat(outcome.failure().statusCode()).isEqualTo(status);
        assertThat(outcome.failure().key()).isEqualTo(key);
        assertThat(outcome.failure().message()).isNotBlank();
        assertThat(outcome.forwarded()).as("nothing forwarded").isNull();
    }

    private static byte[] json(String format, Object... args) {
        return String.format(format, args).getBytes(StandardCharsets.UTF_8);
    }

    static byte[] fixture(String name) {
        try (var in = WebhookSignaturePolicyTest.class.getResourceAsStream("/fixtures/" + name)) {
            return Objects.requireNonNull(in, name).readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
