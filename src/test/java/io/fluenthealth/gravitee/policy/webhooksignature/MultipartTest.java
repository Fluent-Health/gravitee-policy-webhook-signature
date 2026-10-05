package io.fluenthealth.gravitee.policy.webhooksignature;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class MultipartTest {

    @Test
    void readsTheMailgunRouteFixture() {
        var fields = Multipart.fields(WebhookSignaturePolicyTest.fixture("mailgun-route.multipart"), WebhookSignaturePolicyTest.Vectors.BOUNDARY);

        assertThat(fields)
            .containsEntry("timestamp", "1749416383")
            .containsEntry("token", WebhookSignaturePolicyTest.Vectors.MAILGUN_TOKEN)
            .containsEntry("signature", WebhookSignaturePolicyTest.Vectors.MAILGUN_SIGNATURE)
            .containsEntry("recipient", "inbox@mg.example.com")
            .doesNotContainKey("attachment-1");
    }

    @Test
    void firstOccurrenceWins() {
        var fields = Multipart.fields(body(part("token", "first"), part("token", "second"), close()), "b");
        assertThat(fields).containsEntry("token", "first");
    }

    @Test
    void ignoresFilePartsEvenWhenTheyShareAFieldName() {
        var file = "--b\r\nContent-Disposition: form-data; name=\"signature\"; filename=\"s.txt\"\r\n\r\nfrom-a-file\r\n";
        var fields = Multipart.fields(body(file, part("signature", "from-a-field"), close()), "b");
        assertThat(fields).containsEntry("signature", "from-a-field");
    }

    @Test
    void doesNotMistakeFilenameForName() {
        var file = "--b\r\nContent-Disposition: form-data; filename=\"token\"\r\n\r\nx\r\n";
        assertThat(Multipart.fields(body(file, close()), "b")).isEmpty();
    }

    @Test
    void keepsAnEmptyValue() {
        assertThat(Multipart.fields(body(part("token", ""), close()), "b")).containsEntry("token", "");
    }

    @Test
    void ignoresAPreambleAndAnEpilogue() {
        var fields = Multipart.fields(body("preamble text\r\n", part("token", "t"), close(), "epilogue --b\r\n"), "b");
        assertThat(fields).containsOnlyKeys("token");
    }

    @Test
    void stopsAtATruncatedBody() {
        var fields = Multipart.fields(body(part("token", "t"), "--b\r\nContent-Disposition: form-data; name=\"signature\"\r\n\r\nabc"), "b");
        assertThat(fields).containsOnlyKeys("token");
    }

    @Test
    void readsNothingFromTheWrongBoundary() {
        assertThat(Multipart.fields(body(part("token", "t"), close()), "other")).isEmpty();
    }

    @Test
    void parsesTheBoundary() {
        assertThat(Multipart.boundary("multipart/form-data; boundary=abc")).isEqualTo("abc");
        assertThat(Multipart.boundary("multipart/form-data; boundary=\"a b:c\"")).isEqualTo("a b:c");
        assertThat(Multipart.boundary("MULTIPART/FORM-DATA; BOUNDARY=abc")).isEqualTo("abc");
        assertThat(Multipart.boundary("multipart/form-data; charset=utf-8; boundary=abc ")).isEqualTo("abc");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { "multipart/form-data", "multipart/form-data; boundary=", "multipart/form-data; boundary=\"\"", "multipart/mixed; boundary=abc", "text/plain; boundary=abc" })
    void rejectsAnUnusableContentType(String contentType) {
        assertThat(Multipart.boundary(contentType)).isNull();
    }

    private static String part(String name, String value) {
        return "--b\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + value + "\r\n";
    }

    private static String close() {
        return "--b--\r\n";
    }

    private static byte[] body(String... parts) {
        return String.join("", parts).getBytes(StandardCharsets.ISO_8859_1);
    }
}
