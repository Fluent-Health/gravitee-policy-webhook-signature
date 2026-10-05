package io.fluenthealth.gravitee.policy.webhooksignature;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Just enough of RFC 7578 {@code multipart/form-data} to read the plain form fields of a body.
 *
 * <p>Read-only by construction: it parses a copy of the bytes and never touches the request. The
 * body is viewed as ISO-8859-1, which maps every byte to exactly one char, so a binary part can
 * never throw or shift offsets — and since only ASCII field values are read back, nothing here
 * depends on what charset a text part was actually in.
 */
final class Multipart {

    private static final Pattern FIELD_NAME = Pattern.compile("(?im)^content-disposition:.*?(?<![\\w*])name=\"([^\"]*)\"");
    private static final Pattern FILE_PART = Pattern.compile("(?im)^content-disposition:.*?\\bfilename\\*?=");

    private Multipart() {}

    /**
     * The boundary of a {@code multipart/form-data} Content-Type, unquoted, or null when the type is
     * anything else or carries no usable boundary.
     */
    static String boundary(String contentType) {
        if (contentType == null) {
            return null;
        }
        var params = contentType.split(";");
        if (!params[0].trim().equalsIgnoreCase("multipart/form-data")) {
            return null;
        }
        for (int i = 1; i < params.length; i++) {
            var param = params[i].trim();
            var eq = param.indexOf('=');
            if (eq > 0 && param.substring(0, eq).trim().toLowerCase(Locale.ROOT).equals("boundary")) {
                var value = param.substring(eq + 1).trim();
                if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1);
                }
                return value.isEmpty() ? null : value;
            }
        }
        return null;
    }

    /**
     * The non-file fields of the body, by name. When a name repeats, the first occurrence wins.
     * Parts without a name, file parts, and anything after the closing delimiter are ignored.
     */
    static Map<String, String> fields(byte[] body, String boundary) {
        var text = new String(body, StandardCharsets.ISO_8859_1);
        var delimiter = "--" + boundary;
        var fields = new LinkedHashMap<String, String>();

        var at = text.startsWith(delimiter) ? 0 : text.indexOf("\r\n" + delimiter);
        if (at > 0) {
            at += 2;
        }
        while (at >= 0) {
            var afterDelimiter = at + delimiter.length();
            if (text.startsWith("--", afterDelimiter)) {
                break;
            }
            var partStart = text.indexOf("\r\n", afterDelimiter);
            if (partStart < 0) {
                break;
            }
            partStart += 2;
            var partEnd = text.indexOf("\r\n" + delimiter, partStart);
            if (partEnd < 0) {
                break;
            }
            readField(text.substring(partStart, partEnd), fields);
            at = partEnd + 2;
        }
        return fields;
    }

    private static void readField(String part, Map<String, String> fields) {
        var headerEnd = part.indexOf("\r\n\r\n");
        if (headerEnd < 0) {
            return;
        }
        var headers = part.substring(0, headerEnd);
        if (FILE_PART.matcher(headers).find()) {
            return;
        }
        var name = FIELD_NAME.matcher(headers);
        if (name.find()) {
            fields.putIfAbsent(name.group(1), part.substring(headerEnd + 4));
        }
    }
}
