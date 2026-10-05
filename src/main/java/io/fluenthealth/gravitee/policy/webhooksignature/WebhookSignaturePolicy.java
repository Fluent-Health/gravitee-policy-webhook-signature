package io.fluenthealth.gravitee.policy.webhooksignature;

import static io.fluenthealth.gravitee.policy.webhooksignature.configuration.WebhookSignaturePolicyConfiguration.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.fluenthealth.gravitee.policy.webhooksignature.configuration.WebhookSignaturePolicyConfiguration;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.policy.http.HttpPolicy;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.core.Single;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies an HMAC-signed inbound webhook and interrupts the request unless the signature matches.
 *
 * <p>Every path that cannot positively establish a valid signature fails closed with a 4xx — a
 * missing or malformed signature, a missing secret, an unreadable body — and nothing on those
 * paths can throw its way to an unexplained 500. The request body is read but never rewritten:
 * the buffer that was verified is the buffer that is forwarded, byte for byte.
 *
 * <p>Each failure carries a stable {@link ExecutionFailure#key() key}, so status and body can be
 * customised per failure with the API's response templates instead of policy configuration.
 */
public class WebhookSignaturePolicy implements HttpPolicy {

    private static final Logger log = LoggerFactory.getLogger(WebhookSignaturePolicy.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final byte[] EMPTY = new byte[0];

    /** No signature was presented: absent or blank header, or missing Mailgun fields. */
    public static final String KEY_MISSING = "WEBHOOK_SIGNATURE_MISSING";
    /** A signature header that does not carry the configured prefix followed by a digest. */
    public static final String KEY_MALFORMED = "WEBHOOK_SIGNATURE_MALFORMED";
    /** A signature was presented and does not match. Includes a digest that does not decode. */
    public static final String KEY_INVALID = "WEBHOOK_SIGNATURE_INVALID";
    /** The secret resolved to nothing — typically a secret that has not been populated yet. */
    public static final String KEY_SECRET_UNAVAILABLE = "WEBHOOK_SIGNATURE_SECRET_UNAVAILABLE";
    /** Resolving the secret expression failed, e.g. the secret provider errored. */
    public static final String KEY_SECRET_UNRESOLVED = "WEBHOOK_SIGNATURE_SECRET_UNRESOLVED";
    /** The body cannot carry a Mailgun signature at all: not JSON, or not multipart. */
    public static final String KEY_BODY_INVALID = "WEBHOOK_SIGNATURE_BODY_INVALID";
    /** The policy configuration is incomplete or invalid. */
    public static final String KEY_MISCONFIGURED = "WEBHOOK_SIGNATURE_MISCONFIGURED";
    /** Verification failed for a reason none of the above describes — a bug, not a sender error. */
    public static final String KEY_ERROR = "WEBHOOK_SIGNATURE_ERROR";

    private final WebhookSignaturePolicyConfiguration configuration;

    public WebhookSignaturePolicy(WebhookSignaturePolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public String id() {
        return "webhook-signature";
    }

    @Override
    public Completable onRequest(HttpPlainExecutionContext ctx) {
        return ctx
            .request()
            .onBody(body ->
                body
                    .map(Optional::of)
                    .defaultIfEmpty(Optional.empty())
                    .flatMapMaybe(original ->
                        verify(ctx, original.map(Buffer::getBytes).orElse(EMPTY))
                            // Forward the very buffer that was verified. Re-encoding it — e.g. through a
                            // String — would mangle every byte of a binary attachment that is not valid UTF-8.
                            .andThen(Maybe.defer(() -> Maybe.fromOptional(original)))
                            .onErrorResumeNext(error -> ctx.interruptBodyWith(toFailure(error)))
                    )
            );
    }

    // ── Verification ──────────────────────────────────────────────────────────

    Completable verify(HttpPlainExecutionContext ctx, byte[] body) {
        return Completable.defer(() -> {
            var problem = configuration.validate();
            if (problem != null) {
                log.error("Webhook signature policy is misconfigured: {}", problem);
                throw new Rejection(500, KEY_MISCONFIGURED, "Webhook signature policy is misconfigured");
            }
            var signed = extract(ctx, body);
            return resolveSecret(ctx).flatMapCompletable(secret -> {
                if (!matches(secret, signed)) {
                    throw new Rejection(401, KEY_INVALID, "Invalid signature");
                }
                return Completable.complete();
            });
        });
    }

    /** The digest as presented by the sender, and the exact bytes it claims to sign. */
    record Signed(String signature, byte[] message) {}

    private Signed extract(HttpPlainExecutionContext ctx, byte[] body) {
        return switch (configuration.getSource()) {
            case SOURCE_HEADER -> fromHeader(ctx, body);
            case SOURCE_MAILGUN_JSON -> fromMailgunJson(body);
            case SOURCE_MAILGUN_MULTIPART -> fromMailgunMultipart(ctx, body);
            default -> throw new IllegalStateException("unreachable: source validated");
        };
    }

    private Signed fromHeader(HttpPlainExecutionContext ctx, byte[] body) {
        var name = configuration.getHeader();
        List<String> values = ctx.request().headers().getAll(name);
        var value = values == null || values.isEmpty() ? null : values.get(0);
        if (value == null || value.isBlank()) {
            throw new Rejection(401, KEY_MISSING, name + " header is missing");
        }
        var prefix = configuration.getPrefix();
        if (!value.startsWith(prefix) || value.length() == prefix.length()) {
            throw new Rejection(401, KEY_MALFORMED, "Malformed " + name + " header");
        }
        return new Signed(value.substring(prefix.length()), body);
    }

    /**
     * Mailgun event webhooks sign {@code timestamp + token} — not the body — and carry all three
     * values inside the JSON body under {@code signature}.
     */
    private static Signed fromMailgunJson(byte[] body) {
        JsonNode root;
        try {
            root = MAPPER.readTree(body);
        } catch (Exception e) {
            root = null;
        }
        // An empty body parses to a MissingNode rather than throwing; it is no more JSON than junk is.
        if (root == null || root.isMissingNode()) {
            throw new Rejection(400, KEY_BODY_INVALID, "Invalid JSON body");
        }
        var sig = root.get("signature");
        var timestamp = scalar(sig, "timestamp");
        var token = scalar(sig, "token");
        var signature = scalar(sig, "signature");
        if (timestamp == null || token == null || signature == null) {
            throw new Rejection(401, KEY_MISSING, "Mailgun signature fields are missing");
        }
        return new Signed(signature, (timestamp + token).getBytes(StandardCharsets.UTF_8));
    }

    private static String scalar(JsonNode parent, String field) {
        if (parent == null || !parent.isObject()) {
            return null;
        }
        var node = parent.get(field);
        if (node == null || !node.isValueNode() || node.isNull()) {
            return null;
        }
        var text = node.asText();
        return text.isEmpty() ? null : text;
    }

    /**
     * Mailgun routes post {@code multipart/form-data} carrying {@code timestamp}, {@code token} and
     * {@code signature} as form fields, signed the same way as event webhooks. A missing field is a
     * 400 here rather than a 401: the request is not a well-formed route delivery at all.
     */
    private static Signed fromMailgunMultipart(HttpPlainExecutionContext ctx, byte[] body) {
        var boundary = Multipart.boundary(ctx.request().headers().get("Content-Type"));
        if (boundary == null) {
            throw new Rejection(400, KEY_BODY_INVALID, "Expected a multipart/form-data body");
        }
        var fields = Multipart.fields(body, boundary);
        var timestamp = nonEmpty(fields.get("timestamp"));
        var token = nonEmpty(fields.get("token"));
        var signature = nonEmpty(fields.get("signature"));
        if (timestamp == null || token == null || signature == null) {
            throw new Rejection(400, KEY_MISSING, "Mailgun signature fields are missing");
        }
        return new Signed(signature, (timestamp + token).getBytes(StandardCharsets.UTF_8));
    }

    private static String nonEmpty(String value) {
        return value == null || value.isEmpty() ? null : value;
    }

    /**
     * Resolves the secret through {@code TemplateEngine.eval} — the only entry point that resolves
     * <em>deferred</em> variables such as {@code {#secrets.get(...)}}. The synchronous entry points
     * hand such an expression back as its own literal text, which would then silently become the
     * HMAC key.
     */
    private Single<String> resolveSecret(HttpPlainExecutionContext ctx) {
        var expression = configuration.getSecret();
        return Maybe
            .defer(() -> ctx.getTemplateEngine().eval(expression, String.class))
            .onErrorResumeNext(e -> {
                log.warn("Failed to resolve the webhook secret: {}", e.toString());
                return Maybe.error(new Rejection(500, KEY_SECRET_UNRESOLVED, "Webhook secret could not be resolved"));
            })
            .filter(secret -> !secret.isEmpty())
            .switchIfEmpty(Single.error(() -> new Rejection(401, KEY_SECRET_UNAVAILABLE, "Webhook secret not configured")));
    }

    private boolean matches(String secret, Signed signed) throws GeneralSecurityException {
        byte[] presented;
        try {
            presented = ENCODING_HEX.equals(configuration.getEncoding())
                ? HexFormat.of().parseHex(signed.signature())
                : Base64.getDecoder().decode(signed.signature());
        } catch (IllegalArgumentException e) {
            // Not a well-formed digest, so it cannot be the right one.
            return false;
        }
        var algorithm = configuration.getAlgorithm();
        var mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), algorithm));
        // Compared as decoded bytes, in constant time: hex case does not matter, and the time taken
        // does not reveal how much of a guess was right.
        return MessageDigest.isEqual(mac.doFinal(signed.message()), presented);
    }

    // ── Failure mapping ───────────────────────────────────────────────────────

    private static ExecutionFailure toFailure(Throwable error) {
        if (error instanceof Rejection rejection) {
            log.debug("Webhook rejected: {} ({})", rejection.key, rejection.status);
            return new ExecutionFailure(rejection.status).key(rejection.key).message(rejection.getMessage());
        }
        log.error("Webhook signature verification failed unexpectedly", error);
        return new ExecutionFailure(500).key(KEY_ERROR).message("Webhook signature verification failed");
    }

    /** An expected refusal. Carries no stack trace: it is control flow, not a fault. */
    static final class Rejection extends RuntimeException {

        final int status;
        final String key;

        Rejection(int status, String key, String message) {
            super(message, null, false, false);
            this.status = status;
            this.key = key;
        }
    }
}
