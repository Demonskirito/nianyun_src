package local.nianyun.bridge;

import burp.api.montoya.MontoyaApi;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Tiny loopback HTTP/1.1 server: one request per connection, bearer token, JSON responses.
 * It binds all interfaces because Docker Desktop reaches the host through the WSL/Hyper-V NIC;
 * the token and the per-call host check are the access boundary.
 */
final class BridgeServer {
    private static final int MAX_BODY_BYTES = 512 * 1024;

    private final MontoyaApi api;
    private final String token;
    private final int port;
    private final Routes routes;
    private final ExecutorService executor = Executors.newFixedThreadPool(4);
    private final AtomicBoolean running = new AtomicBoolean(false);
    private ServerSocket socket;

    BridgeServer(MontoyaApi api, String token, int port) {
        this.api = api;
        this.token = token;
        this.port = port;
        this.routes = new Routes(api);
    }

    void start() throws IOException {
        socket = new ServerSocket();
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress("0.0.0.0", port));
        running.set(true);
        Thread acceptor = new Thread(this::acceptLoop, "nianyun-bridge-accept");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    void stop() {
        running.set(false);
        try {
            if (socket != null) socket.close();
        } catch (IOException ignored) { /* shutdown best effort */ }
        executor.shutdownNow();
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket client = socket.accept();
                executor.submit(() -> handle(client));
            } catch (IOException error) {
                if (running.get()) api.logging().logToError("Nianyun Burp Bridge accept failed: " + error.getMessage());
            }
        }
    }

    private void handle(Socket client) {
        try (client) {
            client.setSoTimeout(20_000);
            Exchange exchange = Exchange.read(client.getInputStream(), client.getOutputStream());
            if (exchange == null) return;
            if (!authorized(exchange)) {
                exchange.send(401, Json.error("unauthorized"));
                return;
            }
            routes.handle(exchange);
        } catch (Throwable error) {
            // Errors (linkage failures, stack overflows inside Burp) must still answer the caller;
            // a closed socket tells the agent nothing about what went wrong.
            
            try {
                OutputStream out = client.getOutputStream();
                byte[] body = (Json.error(error.getClass().getSimpleName() + ": " + error.getMessage())).getBytes(StandardCharsets.UTF_8);
                String head = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: "
                        + body.length + "\r\nConnection: close\r\n\r\n";
                out.write(head.getBytes(StandardCharsets.UTF_8));
                out.write(body);
                out.flush();
            } catch (Exception ignored) {
                // The socket is already gone; nothing else to do.
            }
            try {
                api.logging().logToError("Nianyun Burp Bridge request failed: " + error);
            } catch (Throwable ignored) {
                // Burp logging is unavailable; the caller already has the error body.
            }
        }
    }

    private boolean authorized(Exchange exchange) {
        String header = exchange.header("authorization");
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) return false;
        byte[] supplied = header.substring(7).getBytes(StandardCharsets.UTF_8);
        byte[] expected = token.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(supplied, expected);
    }

    /** One parsed request plus the response writer; routing decides what to do with it. */
    static final class Exchange {
        private final String method;
        private final URI uri;
        private final Map<String, String> headers;
        private final byte[] body;
        private final OutputStream output;

        private Exchange(String method, URI uri, Map<String, String> headers, byte[] body, OutputStream output) {
            this.method = method;
            this.uri = uri;
            this.headers = headers;
            this.body = body;
            this.output = output;
        }

        static Exchange read(InputStream input, OutputStream output) throws IOException {
            String requestLine = readLine(input);
            if (requestLine == null || requestLine.isBlank()) return null;
            String[] parts = requestLine.split(" ");
            if (parts.length < 3) return null;
            Map<String, String> headers = new HashMap<>();
            String line;
            while ((line = readLine(input)) != null && !line.isEmpty()) {
                int colon = line.indexOf(':');
                if (colon > 0) headers.put(line.substring(0, colon).trim().toLowerCase(Locale.ROOT), line.substring(colon + 1).trim());
            }
            byte[] body = new byte[0];
            String lengthHeader = headers.get("content-length");
            if (lengthHeader != null) {
                int length;
                try {
                    length = Integer.parseInt(lengthHeader.trim());
                } catch (NumberFormatException invalid) {
                    length = 0;
                }
                if (length > 0) {
                    if (length > MAX_BODY_BYTES) throw new IOException("request body exceeds the bridge limit");
                    body = input.readNBytes(length);
                }
            }
            return new Exchange(parts[0].toUpperCase(Locale.ROOT), URI.create(parts[1]), headers, body, output);
        }

        private static String readLine(InputStream input) throws IOException {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int current;
            while ((current = input.read()) != -1) {
                if (current == '\n') break;
                if (current != '\r') buffer.write(current);
                if (buffer.size() > 16 * 1024) return null;
            }
            if (current == -1 && buffer.size() == 0) return null;
            return buffer.toString(StandardCharsets.UTF_8);
        }

        String method() { return method; }
        URI uri() { return uri; }
        String path() { return uri.getPath(); }
        byte[] body() { return body; }
        String bodyText() { return new String(body, StandardCharsets.UTF_8); }

        String query(String name) {
            String raw = uri.getRawQuery();
            if (raw == null || raw.isEmpty()) return null;
            for (String pair : raw.split("&")) {
                String[] item = pair.split("=", 2);
                String key = decode(item[0]);
                if (!name.equals(key)) continue;
                return item.length == 2 ? decode(item[1]) : "";
            }
            return null;
        }

        java.util.List<String> queryAll(String name) {
            java.util.List<String> values = new java.util.ArrayList<>();
            String raw = uri.getRawQuery();
            if (raw == null || raw.isEmpty()) return values;
            for (String pair : raw.split("&")) {
                String[] item = pair.split("=", 2);
                if (!name.equals(decode(item[0]))) continue;
                values.add(item.length == 2 ? decode(item[1]) : "");
            }
            return values;
        }

        private static String decode(String value) {
            try {
                return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
            } catch (RuntimeException ignored) {
                return value;
            }
        }

        String header(String name) { return headers.get(name.toLowerCase(Locale.ROOT)); }

        void send(int status, String json) throws IOException {
            byte[] payload = json.getBytes(StandardCharsets.UTF_8);
            String reason = switch (status) {
                case 200 -> "OK";
                case 400 -> "Bad Request";
                case 401 -> "Unauthorized";
                case 404 -> "Not Found";
                case 405 -> "Method Not Allowed";
                case 413 -> "Payload Too Large";
                case 502 -> "Bad Gateway";
                default -> "Error";
            };
            String head = "HTTP/1.1 " + status + " " + reason + "\r\n"
                    + "Content-Type: application/json; charset=utf-8\r\n"
                    + "Cache-Control: no-store\r\n"
                    + "X-Content-Type-Options: nosniff\r\n"
                    + "X-Nianyun-Bridge-Version: 3\r\n"
                    + "Content-Length: " + payload.length + "\r\n"
                    + "Connection: close\r\n\r\n";
            output.write(head.getBytes(StandardCharsets.UTF_8));
            output.write(payload);
            output.flush();
        }
    }
}