package io.fluenthealth.gravitee.policy.webhooksignature.configuration;

import io.gravitee.policy.api.PolicyConfiguration;
import java.util.Set;

/**
 * Deliberately flat and with <em>no defaults</em>: every field starts out null, and a missing value
 * fails the request closed rather than being filled in. That way an API definition always states
 * the whole contract, and there is no hidden default for a caller to mirror or drift from.
 */
public class WebhookSignaturePolicyConfiguration implements PolicyConfiguration {

    /** The signature is a request header; the signed message is the raw request body. GitHub, Sentry, Meta. */
    public static final String SOURCE_HEADER = "header";

    /** Mailgun event webhooks: a JSON body carrying {@code signature.{timestamp,token,signature}}. */
    public static final String SOURCE_MAILGUN_JSON = "mailgun-json";

    /** Mailgun routes: a {@code multipart/form-data} body carrying {@code timestamp}, {@code token}, {@code signature} fields. */
    public static final String SOURCE_MAILGUN_MULTIPART = "mailgun-multipart";

    public static final Set<String> SOURCES = Set.of(SOURCE_HEADER, SOURCE_MAILGUN_JSON, SOURCE_MAILGUN_MULTIPART);

    public static final Set<String> ALGORITHMS = Set.of("HmacSHA1", "HmacSHA256", "HmacSHA512");

    public static final String ENCODING_HEX = "hex";

    public static final String ENCODING_BASE64 = "base64";

    public static final Set<String> ENCODINGS = Set.of(ENCODING_HEX, ENCODING_BASE64);

    private String source;

    /** Header carrying the signature. Required when {@code source} is {@code header}, ignored otherwise. */
    private String header;

    /**
     * Literal text preceding the digest in the header value, e.g. {@code sha256=}. Required when
     * {@code source} is {@code header} — the empty string, not null, when the provider sends a bare
     * digest, so "no prefix" is always a stated choice.
     */
    private String prefix;

    /** A JCA {@link javax.crypto.Mac} algorithm name — one of {@link #ALGORITHMS}. */
    private String algorithm;

    /** How the received digest is encoded — one of {@link #ENCODINGS}. */
    private String encoding;

    /** The HMAC key. May be a template expression, including a deferred {@code {#secrets.get(...)}}. */
    private String secret;

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getHeader() {
        return header;
    }

    public void setHeader(String header) {
        this.header = header;
    }

    public String getPrefix() {
        return prefix;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getEncoding() {
        return encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    /**
     * Describes the first problem that makes this configuration unusable, or returns null when it
     * is complete. Checked per request rather than at construction, because a policy that cannot
     * be built fails the whole API deployment, while one that answers 500 fails only its own flow.
     */
    public String validate() {
        if (source == null || !SOURCES.contains(source)) {
            return "source must be one of " + SOURCES;
        }
        if (algorithm == null || !ALGORITHMS.contains(algorithm)) {
            return "algorithm must be one of " + ALGORITHMS;
        }
        if (encoding == null || !ENCODINGS.contains(encoding)) {
            return "encoding must be one of " + ENCODINGS;
        }
        if (secret == null) {
            return "secret is required";
        }
        if (SOURCE_HEADER.equals(source)) {
            if (header == null || header.isBlank()) {
                return "header is required when source is 'header'";
            }
            if (prefix == null) {
                return "prefix is required when source is 'header' (use \"\" for a bare digest)";
            }
        }
        return null;
    }
}
