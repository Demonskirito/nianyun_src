package local.nianyun.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.extension.ExtensionWebSocket;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation;
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Agent-driven WebSocket sessions.
 *
 * Burp exposes WebSocket creation only to extensions, so the bridge opens the connection through
 * {@code websockets().createWebSocket(...)} and buffers every inbound frame. The agent can then send
 * text or binary frames and pull what came back — the step that was missing while only
 * {@code /ws/history} existed.
 */
final class Ws {

    private static final int MAX_MESSAGES = 2000;
    private static final int MAX_TEXT = 4096;

    private static Ws instance;

    static synchronized Ws sessions(MontoyaApi api) {
        if (instance == null) instance = new Ws(api);
        return instance;
    }

    private final MontoyaApi api;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    private Ws(MontoyaApi api) {
        this.api = api;
    }

    Map<String, Object> open(String url, String protocol, Map<String, Object> headers, int timeoutMs) {
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException error) {
            throw new Routes.BadRequest("invalid websocket url: " + error.getMessage());
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
        boolean secure = scheme.equals("wss") || scheme.equals("https");
        if (!secure && !scheme.equals("ws") && !scheme.equals("http")) {
            throw new Routes.BadRequest("websocket url must start with ws:// or wss://");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) throw new Routes.BadRequest("websocket url has no host");
        int port = uri.getPort() > 0 ? uri.getPort() : (secure ? 443 : 80);
        String path = uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath();
        if (uri.getRawQuery() != null && !uri.getRawQuery().isBlank()) path = path + "?" + uri.getRawQuery();

        byte[] key = new byte[16];
        random.nextBytes(key);
        StringBuilder raw = new StringBuilder();
        raw.append("GET ").append(path).append(" HTTP/1.1\r\n");
        int defaultPort = secure ? 443 : 80;
        raw.append("Host: ").append(host).append(port == defaultPort ? "" : ":" + port).append("\r\n");
        raw.append("Upgrade: websocket\r\n");
        raw.append("Connection: Upgrade\r\n");
        raw.append("Sec-WebSocket-Key: ").append(Base64.getEncoder().encodeToString(key)).append("\r\n");
        raw.append("Sec-WebSocket-Version: 13\r\n");
        if (protocol != null && !protocol.isBlank()) raw.append("Sec-WebSocket-Protocol: ").append(protocol).append("\r\n");
        for (Map.Entry<String, Object> entry : headers.entrySet()) {
            raw.append(entry.getKey()).append(": ").append(String.valueOf(entry.getValue())).append("\r\n");
        }
        raw.append("\r\n");

        HttpService service = HttpService.httpService(host, port, secure);
        HttpRequest upgrade = HttpRequest.httpRequest(service, raw.toString());

        ExtensionWebSocketCreation creation;
        try {
            creation = api.websockets().createWebSocket(upgrade);
        } catch (RuntimeException error) {
            throw new Routes.BadRequest("Burp could not open the websocket: " + describe(error));
        }
        String status = String.valueOf(creation.status());
        Optional<ExtensionWebSocket> socket = creation.webSocket();
        if (socket.isEmpty()) {
            String upgradeStatus = creation.upgradeResponse().map(response -> "status " + response.statusCode()).orElse("no upgrade response");
            throw new Routes.BadRequest("websocket upgrade failed (" + status + ", " + upgradeStatus + ")");
        }
        Session session = new Session(socket.get(), url);
        session.socket.registerMessageHandler(session);
        sessions.put(session.id, session);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("session_id", session.id);
        out.put("url", url);
        out.put("protocol", protocol == null ? "" : protocol);
        out.put("status", status);
        out.put("upgrade_status", creation.upgradeResponse().map(response -> (int) response.statusCode()).orElse(0));
        return out;
    }

    Map<String, Object> send(String id, String kind, String data) {
        Session session = require(id);
        if (kind.equalsIgnoreCase("binary")) {
            byte[] bytes = data.isEmpty() ? new byte[0] : java.util.HexFormat.of().parseHex(data.replace(" ", ""));
            session.socket.sendBinaryMessage(ByteArray.byteArray(bytes));
            session.record("out", "binary", bytes.length + " bytes", bytes.length);
        } else {
            session.socket.sendTextMessage(data);
            session.record("out", "text", data, data.length());
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("session_id", session.id);
        out.put("sent", kind);
        out.put("bytes", data.length());
        return out;
    }

    Map<String, Object> messages(String id, int since) {
        Session session = require(id);
        List<Object> rows = new ArrayList<>();
        for (Map<String, Object> message : session.snapshot()) {
            int index = ((Number) message.get("index")).intValue();
            if (index >= since) rows.add(message);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("session_id", session.id);
        out.put("total", session.received.get());
        out.put("messages", rows);
        return out;
    }

    Map<String, Object> close(String id) {
        Session session = require(id);
        try {
            session.socket.close();
        } catch (RuntimeException ignored) {
            // Already closed by the server; the session is dropped either way.
        }
        sessions.remove(id);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("session_id", id);
        out.put("closed", true);
        return out;
    }

    Map<String, Object> list() {
        List<Object> rows = new ArrayList<>();
        for (Session session : sessions.values()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("session_id", session.id);
            row.put("url", session.url);
            row.put("opened_at", session.openedAt);
            row.put("received", session.received.get());
            row.put("sent", session.sent.get());
            rows.add(row);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("total", rows.size());
        out.put("sessions", rows);
        return out;
    }

    private Session require(String id) {
        if (id == null || id.isBlank()) throw new Routes.BadRequest("session_id is required");
        Session session = sessions.get(id);
        if (session == null) throw new Routes.BadRequest("unknown websocket session: " + id);
        return session;
    }

    private static String describe(Throwable error) {
        String message = error.getMessage();
        return error.getClass().getSimpleName() + (message == null ? "" : " - " + message);
    }

    /** One open socket plus a bounded frame buffer. */
    private static final class Session implements ExtensionWebSocketMessageHandler {
        private final String id = "ws-" + Long.toHexString(System.nanoTime());
        private final ExtensionWebSocket socket;
        private final String url;
        private final long openedAt = System.currentTimeMillis();
        private final AtomicInteger received = new AtomicInteger();
        private final AtomicInteger sent = new AtomicInteger();
        private final List<Map<String, Object>> buffer = java.util.Collections.synchronizedList(new ArrayList<>());
        private int sequence;

        private Session(ExtensionWebSocket socket, String url) {
            this.socket = socket;
            this.url = url;
        }

        @Override
        public void textMessageReceived(TextMessage message) {
            record("in", "text", message.payload(), message.payload() == null ? 0 : message.payload().length());
        }

        @Override
        public void binaryMessageReceived(BinaryMessage message) {
            byte[] bytes = message.payload() == null ? new byte[0] : message.payload().getBytes();
            record("in", "binary", java.util.HexFormat.of().formatHex(bytes), bytes.length);
        }

        private void record(String direction, String kind, String data, int bytes) {
            if (direction.equals("in")) received.incrementAndGet();
            else sent.incrementAndGet();
            String text = data == null ? "" : data;
            if (text.length() > MAX_TEXT) text = text.substring(0, MAX_TEXT);
            Map<String, Object> row = new LinkedHashMap<>();
            synchronized (buffer) {
                row.put("index", sequence++);
                row.put("direction", direction);
                row.put("kind", kind);
                row.put("bytes", bytes);
                row.put("at", System.currentTimeMillis());
                row.put("payload", text);
                buffer.add(row);
                while (buffer.size() > MAX_MESSAGES) buffer.remove(0);
            }
        }

        private List<Map<String, Object>> snapshot() {
            synchronized (buffer) {
                return new ArrayList<>(buffer);
            }
        }
    }
}