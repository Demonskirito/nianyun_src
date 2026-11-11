package local.nianyun.bridge;

import burp.api.montoya.http.message.HttpMessage;

import java.util.regex.Pattern;

/**
 * The bridge is the only component that sees raw Burp traffic, so redaction happens here:
 * credentials in headers, query strings and form/JSON bodies never reach the agent or the ledger.
 */
final class Redaction {
    private static final Pattern SENSITIVE_HEADER = Pattern.compile(
            "(?i)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)\\s*:.*$");
    private static final Pattern SENSITIVE_BODY_FIELD = Pattern.compile(
            "(?i)(\"?(?:password|passwd|secret|token|access[_-]?token|refresh[_-]?token|client[_-]?secret|api[_-]?key|authorization)\"?\\s*[:=]\\s*)(\"(?:\\\\.|[^\"\\\\])*\"|[^,}\\]\\s&]+)");
    private static final Pattern QUERY_SECRET = Pattern.compile(
            "(?i)([?&](?:password|passwd|secret|token|access_token|refresh_token|api_key|apikey|authorization)=)[^&]*");

    private Redaction() {}

    static String url(String raw) {
        if (raw == null) return "";
        return QUERY_SECRET.matcher(raw).replaceAll("$1[REDACTED]");
    }

    static String text(String value) {
        return value == null ? "" : SENSITIVE_BODY_FIELD.matcher(value).replaceAll("$1\"[REDACTED]\"");
    }

    static String message(HttpMessage message) {
        if (message == null) return "";
        String[] parts = message.toString().split("\r?\n\r?\n", 2);
        String[] lines = parts[0].split("\r?\n", -1);
        if (lines.length > 0) lines[0] = url(lines[0]);
        for (int i = 1; i < lines.length; i++) {
            if (SENSITIVE_HEADER.matcher(lines[i]).matches()) {
                lines[i] = lines[i].substring(0, lines[i].indexOf(':') + 1) + " [REDACTED]";
            }
        }
        String headers = String.join("\r\n", lines);
        if (parts.length == 1) return headers;
        return headers + "\r\n\r\n" + text(parts[1]);
    }
}