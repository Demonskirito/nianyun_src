package local.nianyun.bridge;

import java.util.List;
import java.util.Map;

/** Minimal JSON writer: the bridge only ever emits flat objects and string arrays. */
final class Json {
    private Json() {}

    static String quote(String value) {
        if (value == null) return "null";
        StringBuilder out = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        return out.append('"').toString();
    }

    static String bool(boolean value) { return value ? "true" : "false"; }

    static String number(long value) { return Long.toString(value); }

    static String pair(String name, String jsonValue) { return quote(name) + ":" + jsonValue; }

    static String object(String... pairs) { return "{" + String.join(",", pairs) + "}"; }

    static String array(List<String> items) { return "[" + String.join(",", items) + "]"; }

    static String strings(Map<String, String> values) {
        StringBuilder out = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : values.entrySet()) {
            if (!first) out.append(',');
            first = false;
            out.append(quote(entry.getKey())).append(':').append(quote(entry.getValue()));
        }
        return out.append('}').toString();
    }

    static String error(String message) {
        return object(pair("ok", "false"), pair("error", quote(message == null ? "unknown error" : message)));
    }

    /** Generic writer for nested maps/lists so engine and control endpoints can return rich JSON. */
    static String write(Object value) {
        StringBuilder out = new StringBuilder();
        render(value, out, 0);
        return out.toString();
    }

    /**
     * Minimal parser for request bodies. Action endpoints take a JSON object so a template can
     * carry newlines and payload lists without inventing a second encoding.
     */
    static Object parse(String text) {
        Parser parser = new Parser(text == null ? "" : text);
        parser.skip();
        if (parser.end()) return null;
        Object value = parser.value();
        parser.skip();
        if (!parser.end()) throw new IllegalArgumentException("trailing characters in JSON body");
        return value;
    }

    private static final class Parser {
        private final String text;
        private int index;

        Parser(String text) { this.text = text; }

        boolean end() { return index >= text.length(); }

        void skip() {
            while (index < text.length() && Character.isWhitespace(text.charAt(index))) index++;
        }

        Object value() {
            skip();
            if (end()) throw new IllegalArgumentException("unexpected end of JSON");
            char c = text.charAt(index);
            return switch (c) {
                case '{' -> object();
                case '[' -> array();
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> number();
            };
        }

        private Object literal(String word, Object value) {
            if (!text.startsWith(word, index)) throw new IllegalArgumentException("invalid JSON literal at " + index);
            index += word.length();
            return value;
        }

        private java.util.Map<String, Object> object() {
            java.util.Map<String, Object> map = new java.util.LinkedHashMap<>();
            index++;
            skip();
            if (!end() && text.charAt(index) == '}') { index++; return map; }
            while (true) {
                skip();
                String key = string();
                skip();
                if (end() || text.charAt(index) != ':') throw new IllegalArgumentException("expected ':' at " + index);
                index++;
                map.put(key, value());
                skip();
                if (end()) throw new IllegalArgumentException("unterminated object");
                char c = text.charAt(index++);
                if (c == '}') return map;
                if (c != ',') throw new IllegalArgumentException("expected ',' or '}' at " + (index - 1));
            }
        }

        private java.util.List<Object> array() {
            java.util.List<Object> list = new java.util.ArrayList<>();
            index++;
            skip();
            if (!end() && text.charAt(index) == ']') { index++; return list; }
            while (true) {
                list.add(value());
                skip();
                if (end()) throw new IllegalArgumentException("unterminated array");
                char c = text.charAt(index++);
                if (c == ']') return list;
                if (c != ',') throw new IllegalArgumentException("expected ',' or ']' at " + (index - 1));
            }
        }

        private String string() {
            if (end() || text.charAt(index) != '"') throw new IllegalArgumentException("expected string at " + index);
            index++;
            StringBuilder out = new StringBuilder();
            while (index < text.length()) {
                char c = text.charAt(index++);
                if (c == '"') return out.toString();
                if (c != '\\') { out.append(c); continue; }
                if (end()) break;
                char escape = text.charAt(index++);
                switch (escape) {
                    case '"' -> out.append('"');
                    case '\\' -> out.append('\\');
                    case '/' -> out.append('/');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (index + 4 > text.length()) throw new IllegalArgumentException("bad unicode escape");
                        out.append((char) Integer.parseInt(text.substring(index, index + 4), 16));
                        index += 4;
                    }
                    default -> throw new IllegalArgumentException("bad escape \\" + escape);
                }
            }
            throw new IllegalArgumentException("unterminated string");
        }

        private Object number() {
            int start = index;
            while (index < text.length() && "+-.eE0123456789".indexOf(text.charAt(index)) >= 0) index++;
            String raw = text.substring(start, index);
            if (raw.isEmpty()) throw new IllegalArgumentException("unexpected character at " + start);
            try {
                if (raw.contains(".") || raw.contains("e") || raw.contains("E")) return Double.parseDouble(raw);
                return Long.parseLong(raw);
            } catch (NumberFormatException error) {
                throw new IllegalArgumentException("bad number: " + raw);
            }
        }
    }

    private static void render(Object value, StringBuilder out, int depth) {
        if (depth > 12) {
            out.append("null");
            return;
        }
        if (value == null) {
            out.append("null");
        } else if (value instanceof String text) {
            out.append(quote(text));
        } else if (value instanceof Boolean flag) {
            out.append(bool(flag));
        } else if (value instanceof Double number) {
            out.append(number.isNaN() || number.isInfinite() ? "null" : number.toString());
        } else if (value instanceof Float number) {
            render(Double.valueOf(number.doubleValue()), out, depth + 1);
        } else if (value instanceof Number number) {
            out.append(number(number.longValue()));
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) out.append(',');
                first = false;
                out.append(quote(String.valueOf(entry.getKey()))).append(':');
                render(entry.getValue(), out, depth + 1);
            }
            out.append('}');
        } else if (value instanceof Iterable<?> items) {
            out.append('[');
            boolean first = true;
            for (Object item : items) {
                if (!first) out.append(',');
                first = false;
                render(item, out, depth + 1);
            }
            out.append(']');
        } else if (value.getClass().isArray()) {
            out.append('[');
            int length = java.lang.reflect.Array.getLength(value);
            for (int i = 0; i < length; i++) {
                if (i > 0) out.append(',');
                render(java.lang.reflect.Array.get(value, i), out, depth + 1);
            }
            out.append(']');
        } else {
            out.append(quote(String.valueOf(value)));
        }
    }
}