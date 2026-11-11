package local.nianyun.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.utilities.CompressionType;
import burp.api.montoya.utilities.DigestAlgorithm;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Burp "Converter" surface: everything Decoder, the hex/base64/URL/HTML utilities and the JSON
 * helper can do, reachable as one operation set so the agent does not need a tool per encoder.
 */
final class Convert {

    private final MontoyaApi api;

    Convert(MontoyaApi api) {
        this.api = api;
    }

    Map<String, Object> run(Map<String, Object> input) {
        String operation = str(input.get("op")).trim().toLowerCase(Locale.ROOT).replace('-', '_');
        String value = str(input.get("value"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("operation", operation);
        switch (operation) {
            case "base64_encode" -> out.put("result", api.utilities().base64Utils().encodeToString(value));
            case "base64_decode" -> out.put("result", new String(api.utilities().base64Utils().decode(value).getBytes(), StandardCharsets.UTF_8));
            case "url_encode" -> out.put("result", api.utilities().urlUtils().encode(value));
            case "url_decode" -> out.put("result", api.utilities().urlUtils().decode(value));
            case "html_encode" -> out.put("result", api.utilities().htmlUtils().encode(value));
            case "html_decode" -> out.put("result", api.utilities().htmlUtils().decode(value));
            case "ascii_hex" -> out.put("result", api.utilities().stringUtils().convertAsciiToHexString(value));
            case "hex_ascii" -> out.put("result", api.utilities().stringUtils().convertHexStringToAscii(value));
            case "hex_encode" -> out.put("result", hex(value.getBytes(StandardCharsets.UTF_8)));
            case "hex_decode" -> out.put("result", new String(unhex(value), StandardCharsets.UTF_8));
            case "digest" -> {
                String algorithm = str(input.get("algorithm"));
                if (algorithm.isEmpty()) algorithm = "sha256";
                DigestAlgorithm digest = digestAlgorithm(algorithm);
                out.put("algorithm", digest.name());
                out.put("result", hex(api.utilities().cryptoUtils()
                        .generateDigest(ByteArray.byteArray(value.getBytes(StandardCharsets.UTF_8)), digest).getBytes()));
            }
            case "compress" -> {
                // Implemented with java.util.zip on purpose: Burp 2024.7.3 answers the DEFLATE
                // branch of its own compression utility with an unsupported-operation stub, which
                // would otherwise look like a broken converter.
                String algorithm = str(input.get("algorithm")).isEmpty() ? "gzip" : str(input.get("algorithm"));
                byte[] packed = pack(value.getBytes(StandardCharsets.UTF_8), algorithm);
                out.put("algorithm", algorithm.toUpperCase(Locale.ROOT));
                out.put("length", packed.length);
                out.put("result_base64", Base64.getEncoder().encodeToString(packed));
            }
            case "decompress" -> {
                String algorithm = str(input.get("algorithm")).isEmpty() ? "gzip" : str(input.get("algorithm"));
                byte[] raw = str(input.get("value_base64")).isEmpty()
                        ? unhex(value)
                        : Base64.getDecoder().decode(str(input.get("value_base64")));
                byte[] plain = unpack(raw, algorithm);
                out.put("algorithm", algorithm.toUpperCase(Locale.ROOT));
                out.put("length", plain.length);
                out.put("result", new String(plain, StandardCharsets.UTF_8));
            }
            case "random" -> {
                int length = Math.max(1, Math.min(4096, intOf(input.get("length"), 16)));
                out.put("result", api.utilities().randomUtils().randomString(length));
            }
            case "number" -> number(input, value, out);
            case "json" -> json(input, out);
            case "jwt_decode" -> jwt(value, out);
            default -> throw new Routes.BadRequest("unknown convert op: " + operation
                    + " (base64_encode, base64_decode, url_encode, url_decode, html_encode, html_decode,"
                    + " ascii_hex, hex_ascii, hex_encode, hex_decode, digest, compress, decompress, random,"
                    + " number, json, jwt_decode)");
        }
        Object result = out.get("result");
        if (result instanceof String text) out.put("length", text.length());
        return out;
    }

    private void number(Map<String, Object> input, String value, Map<String, Object> out) {
        String from = str(input.get("from")).trim().toLowerCase(Locale.ROOT);
        String to = str(input.get("to")).trim().toLowerCase(Locale.ROOT);
        if (from.isEmpty()) from = "decimal";
        if (to.isEmpty()) to = "hex";
        String result;
        if (!from.equals("binary") && !from.equals("octal") && !from.equals("decimal") && !from.equals("hex")) {
            throw new Routes.BadRequest("from must be binary, octal, decimal or hex");
        }
        result = switch (from + ">" + to) {
            case "binary>octal" -> api.utilities().numberUtils().convertBinaryToOctal(value);
            case "binary>decimal" -> api.utilities().numberUtils().convertBinaryToDecimal(value);
            case "binary>hex" -> api.utilities().numberUtils().convertBinaryToHex(value);
            case "octal>binary" -> api.utilities().numberUtils().convertOctalToBinary(value);
            case "octal>decimal" -> api.utilities().numberUtils().convertOctalToDecimal(value);
            case "octal>hex" -> api.utilities().numberUtils().convertOctalToHex(value);
            case "decimal>binary" -> api.utilities().numberUtils().convertDecimalToBinary(value);
            case "decimal>octal" -> api.utilities().numberUtils().convertDecimalToOctal(value);
            case "decimal>hex" -> api.utilities().numberUtils().convertDecimalToHex(value);
            case "hex>binary" -> api.utilities().numberUtils().convertHexToBinary(value);
            case "hex>octal" -> api.utilities().numberUtils().convertHexToOctal(value);
            case "hex>decimal" -> api.utilities().numberUtils().convertHexToDecimal(value);
            default -> throw new Routes.BadRequest("unsupported conversion: " + from + " -> " + to);
        };
        out.put("from", from);
        out.put("to", to);
        out.put("result", result);
    }

    private void json(Map<String, Object> input, Map<String, Object> out) {
        String op = str(input.get("action")).trim().toLowerCase(Locale.ROOT);
        if (op.isEmpty()) op = "valid";
        String document = str(input.get("document"));
        String path = str(input.get("path"));
        String value = str(input.get("value"));
        out.put("action", op);
        switch (op) {
            case "valid" -> out.put("result", api.utilities().jsonUtils().isValidJson(document) ? "true" : "false");
            case "read" -> out.put("result", api.utilities().jsonUtils().read(document, path));
            case "add" -> out.put("result", api.utilities().jsonUtils().add(document, path, value));
            case "update" -> out.put("result", api.utilities().jsonUtils().update(document, path, value));
            case "remove" -> out.put("result", api.utilities().jsonUtils().remove(document, path));
            default -> throw new Routes.BadRequest("json action must be valid, read, add, update or remove");
        }
    }

    private static void jwt(String token, Map<String, Object> out) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) throw new Routes.BadRequest("not a JWT: expected header.payload.signature");
        Base64.Decoder decoder = Base64.getUrlDecoder();
        out.put("header", new String(decoder.decode(pad(parts[0])), StandardCharsets.UTF_8));
        out.put("payload", new String(decoder.decode(pad(parts[1])), StandardCharsets.UTF_8));
        out.put("signed", parts.length > 2 && !parts[2].isEmpty());
        out.put("result", new String(decoder.decode(pad(parts[1])), StandardCharsets.UTF_8));
    }

    private static String pad(String base64Url) {
        int remainder = base64Url.length() % 4;
        return remainder == 0 ? base64Url : base64Url + "====".substring(remainder);
    }

    private static DigestAlgorithm digestAlgorithm(String name) {
        String wanted = name.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        for (DigestAlgorithm algorithm : DigestAlgorithm.values()) {
            if (algorithm.name().equals(wanted)) return algorithm;
        }
        // Accept common aliases so "sha1" and "sha-256" both work.
        String compact = wanted.replace("_", "");
        for (DigestAlgorithm algorithm : DigestAlgorithm.values()) {
            if (algorithm.name().replace("_", "").equals(compact)) return algorithm;
        }
        throw new Routes.BadRequest("unknown digest algorithm: " + name);
    }

    private static CompressionType compression(String name) {
        String wanted = name.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        for (CompressionType type : CompressionType.values()) {
            if (type.name().equals(wanted)) return type;
        }
        String compact = wanted.replace("_", "");
        for (CompressionType type : CompressionType.values()) {
            if (type.name().replace("_", "").equals(compact)) return type;
        }
        throw new Routes.BadRequest("unknown compression type: " + name);
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) out.append(String.format("%02x", value));
        return out.toString();
    }

    private static byte[] unhex(String text) {
        String clean = text.replaceAll("\\s+", "");
        if (clean.length() % 2 != 0) throw new Routes.BadRequest("hex input must have an even number of digits");
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static int intOf(Object value, int fallback) {
        if (value instanceof Number number) return number.intValue();
        try {
            return value == null ? fallback : Integer.parseInt(String.valueOf(value).trim());
        } catch (RuntimeException ignored) {
            return fallback;
        }
    }

    private static String str(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static byte[] pack(byte[] data, String algorithm) {
        String name = algorithm.trim().toLowerCase(Locale.ROOT);
        try {
            if (name.equals("deflate") || name.equals("raw") || name.equals("zlib")) {
                java.util.zip.Deflater deflater = new java.util.zip.Deflater(java.util.zip.Deflater.DEFAULT_COMPRESSION, true);
                deflater.setInput(data);
                deflater.finish();
                java.io.ByteArrayOutputStream sink = new java.io.ByteArrayOutputStream();
                byte[] chunk = new byte[8192];
                while (!deflater.finished()) {
                    int written = deflater.deflate(chunk);
                    sink.write(chunk, 0, written);
                }
                deflater.end();
                return sink.toByteArray();
            }
            java.io.ByteArrayOutputStream sink = new java.io.ByteArrayOutputStream();
            try (java.util.zip.GZIPOutputStream gzip = new java.util.zip.GZIPOutputStream(sink)) {
                gzip.write(data);
            }
            return sink.toByteArray();
        } catch (java.io.IOException error) {
            throw new Routes.BadRequest("compress failed: " + error.getMessage());
        }
    }

    private static byte[] unpack(byte[] data, String algorithm) {
        String name = algorithm.trim().toLowerCase(Locale.ROOT);
        try {
            if (name.equals("deflate") || name.equals("raw") || name.equals("zlib")) {
                java.util.zip.Inflater inflater = new java.util.zip.Inflater(true);
                inflater.setInput(data);
                java.io.ByteArrayOutputStream sink = new java.io.ByteArrayOutputStream();
                byte[] chunk = new byte[8192];
                while (!inflater.finished()) {
                    int written = inflater.inflate(chunk);
                    if (written == 0 && inflater.needsInput()) break;
                    sink.write(chunk, 0, written);
                }
                inflater.end();
                return sink.toByteArray();
            }
            try (java.util.zip.GZIPInputStream gzip = new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(data))) {
                return gzip.readAllBytes();
            }
        } catch (java.io.IOException | java.util.zip.DataFormatException error) {
            throw new Routes.BadRequest("decompress failed: " + error.getMessage());
        }
    }
}
