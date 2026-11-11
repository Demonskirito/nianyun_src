package local.nianyun.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.websocket.Direction;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Route table for the Nianyun bridge. Everything is scoped to one host per request: the caller
 * passes the session target host and every URL the bridge touches must match it. The extension
 * never exposes Burp UI actions that the agent cannot justify, and each write endpoint is gated
 * client-side by a rule switch (see docs/tool-capability.md).
 */
final class Routes {
    private static final int MAX_PAGE = 100;
    private static final int MAX_MESSAGE_BYTES = 48 * 1024;
    private static final int MAX_BODY_PREVIEW = 32 * 1024;
    private static final int MAX_RESPONSE_HEADERS = 40;
    private static final List<String> ALLOWED_METHODS = List.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");

    private final MontoyaApi api;
    private final Actions actions;
    /** Audit registry shared with {@link Actions} so report/issue routes see the same audits. */
    static final Map<String, Audit> audits = new ConcurrentHashMap<>();
    private final Map<String, String> auditHosts = new ConcurrentHashMap<>();
    private CollaboratorClient collaborator;

    Routes(MontoyaApi api) {
        this.api = api;
        this.actions = new Actions(api);
    }

    static Map<String, Audit> auditsOf() {
        return audits;
    }

    void handle(BridgeServer.Exchange exchange) throws IOException {
        String path = exchange.path();
        try {
            switch (path) {
                case "/health" -> health(exchange);
                case "/proxy/history" -> history(exchange);
                case "/proxy/entry" -> entry(exchange);
                case "/sitemap" -> siteMap(exchange);
                case "/issues" -> issues(exchange);
                case "/ws/history" -> webSocketHistory(exchange);
                case "/scope" -> scope(exchange);
                case "/intercept" -> intercept(exchange);
                case "/decoder" -> decoder(exchange);
                case "/http/send" -> send(exchange);
                case "/repeater" -> repeater(exchange);
                case "/organizer" -> organizer(exchange);
                case "/collab/generate" -> collaboratorGenerate(exchange);
                case "/collab/poll" -> collaboratorPoll(exchange);
                case "/scan/audit" -> scanAudit(exchange);
                case "/scan/status" -> scanStatus(exchange);
                case "/scan/stop" -> scanStop(exchange);
                // Full-surface endpoints: Burp control, Intruder, analysis, conversion, storage.
                case "/info" -> actions.info(exchange);
                case "/options/export" -> actions.optionsExport(exchange);
                case "/control" -> actions.control(exchange);
                case "/cookies" -> actions.cookies(exchange);
                case "/storage" -> actions.storage(exchange);
                case "/sitemap/issues" -> actions.siteMapIssues(exchange);
                case "/sitemap/add" -> actions.siteMapAdd(exchange);
                case "/scope/edit" -> actions.scopeEdit(exchange);
                case "/http/send_batch" -> actions.sendBatch(exchange);
                case "/crawl" -> actions.crawl(exchange);
                case "/crawl/status" -> actions.crawlStatus(exchange);
                case "/scan/issues" -> actions.scanIssues(exchange);
                case "/scan/report" -> actions.scanReport(exchange);
                case "/intruder" -> actions.intruder(exchange);
                case "/intruder/status" -> actions.intruderStatus(exchange);
                case "/intruder/stop" -> actions.intruderStop(exchange);
                case "/intruder/send" -> actions.intruderSend(exchange);
                case "/compare" -> actions.compare(exchange);
                case "/convert" -> actions.convert(exchange);
            case "/rules" -> actions.rules(exchange);
            case "/websocket" -> actions.websocket(exchange);
            case "/bchecks" -> actions.bchecks(exchange);
                default -> exchange.send(404, Json.error("unknown endpoint: " + path));
            }
        } catch (BadRequest error) {
            exchange.send(400, Json.error(error.getMessage()));
        }
    }

    // ---------------------------------------------------------------- read routes

    private void health(BridgeServer.Exchange exchange) throws IOException {
        requireGet(exchange);
        exchange.send(200, Json.object(
                Json.pair("ok", "true"),
                Json.pair("name", Json.quote("nianyun-burp-bridge")),
                Json.pair("version", "4"),
                Json.pair("capabilities", Json.array(List.of(
                        Json.quote("proxy.history"), Json.quote("proxy.entry"), Json.quote("sitemap"),
                        Json.quote("issues"), Json.quote("ws.history"), Json.quote("scope"),
                        Json.quote("intercept"), Json.quote("decoder"), Json.quote("http.send"),
                        Json.quote("repeater"), Json.quote("organizer"), Json.quote("collaborator"),
                        Json.quote("scan"), Json.quote("info"), Json.quote("control"),
                        Json.quote("cookies"), Json.quote("storage"), Json.quote("sitemap.add"),
                        Json.quote("sitemap.issues"), Json.quote("scope.edit"), Json.quote("http.send_batch"),
                        Json.quote("crawl"), Json.quote("crawl.status"), Json.quote("scan.issues"),
                        Json.quote("scan.report"), Json.quote("intruder"), Json.quote("intruder.status"),
                        Json.quote("rules"), Json.quote("websocket"), Json.quote("bchecks"),
                        Json.quote("intruder.stop"), Json.quote("intruder.send"), Json.quote("compare"),
                        Json.quote("convert"), Json.quote("options.export"))))));
    }

    private void history(BridgeServer.Exchange exchange) throws IOException {
        requireGet(exchange);
        String host = requireHost(exchange);
        List<ProxyHttpRequestResponse> rows = new ArrayList<>();
        for (ProxyHttpRequestResponse item : api.proxy().history()) {
            if (matchesHost(item.finalRequest().url(), host)) rows.add(item);
        }
        int offset = boundedInt(exchange.query("offset"), 0, 0, 100_000);
        int limit = boundedInt(exchange.query("limit"), 30, 1, MAX_PAGE);
        List<String> entries = new ArrayList<>();
        for (int i = offset; i < Math.min(rows.size(), offset + limit); i++) {
            ProxyHttpRequestResponse item = rows.get(i);
            boolean hasResponse = item.hasResponse();
            entries.add(Json.object(
                    Json.pair("entry_id", Json.quote(proxyEntryId(item))),
                    Json.pair("url", Json.quote(Redaction.url(item.finalRequest().url()))),
                    Json.pair("method", Json.quote(item.finalRequest().method())),
                    Json.pair("status", Json.number(hasResponse ? item.response().statusCode() : 0)),
                    Json.pair("timestamp", Json.number(item.time().withZoneSameInstant(ZoneOffset.UTC).toInstant().toEpochMilli())),
                    Json.pair("response_bytes", Json.number(hasResponse ? item.response().body().length() : 0)),
                    Json.pair("content_type", Json.quote(hasResponse ? safe(item.response().headerValue("Content-Type")) : ""))));
        }
        exchange.send(200, Json.object(
                Json.pair("ok", "true"), Json.pair("total", Json.number(rows.size())),
                Json.pair("offset", Json.number(offset)), Json.pair("limit", Json.number(limit)),
                Json.pair("entries", Json.array(entries))));
    }

    private void entry(BridgeServer.Exchange exchange) throws IOException {
        requireGet(exchange);
        String host = requireHost(exchange);
        String id = safe(exchange.query("id"));
        if (!id.matches("(?:proxy|sitemap):[a-f0-9]{16}")) throw new BadRequest("valid entry_id is required");
        if (id.startsWith("proxy:")) {
            for (ProxyHttpRequestResponse item : api.proxy().history()) {
                if (!matchesHost(item.finalRequest().url(), host)) continue;
                if (!proxyEntryId(item).equals(id)) continue;
                exchange.send(200, Json.object(
                        Json.pair("ok", "true"), Json.pair("entry_id", Json.quote(id)),
                        Json.pair("url", Json.quote(Redaction.url(item.finalRequest().url()))),
                        Json.pair("method", Json.quote(item.finalRequest().method())),
                        Json.pair("status", Json.number(item.hasResponse() ? item.response().statusCode() : 0)),
                        Json.pair("request", Json.quote(limitUtf8(Redaction.message(item.finalRequest()), MAX_MESSAGE_BYTES))),
                        Json.pair("response", Json.quote(item.hasResponse() ? limitUtf8(Redaction.message(item.response()), MAX_MESSAGE_BYTES) : "")),
                        Json.pair("redacted", "true")));
                return;
            }
        } else {
            for (HttpRequestResponse item : siteMapRows(host)) {
                if (!siteMapEntryId(item).equals(id)) continue;
                exchange.send(200, Json.object(
                        Json.pair("ok", "true"), Json.pair("entry_id", Json.quote(id)),
                        Json.pair("url", Json.quote(Redaction.url(item.request().url()))),
                        Json.pair("method", Json.quote(item.request().method())),
                        Json.pair("status", Json.number(item.hasResponse() ? item.response().statusCode() : 0)),
                        Json.pair("request", Json.quote(limitUtf8(Redaction.message(item.request()), MAX_MESSAGE_BYTES))),
                        Json.pair("response", Json.quote(item.hasResponse() ? limitUtf8(Redaction.message(item.response()), MAX_MESSAGE_BYTES) : "")),
                        Json.pair("redacted", "true")));
                return;
            }
        }
        exchange.send(404, Json.error("entry not found for this host"));
    }

    private void siteMap(BridgeServer.Exchange exchange) throws IOException {
        requireGet(exchange);
        String host = requireHost(exchange);
        List<HttpRequestResponse> rows = siteMapRows(host);
        int offset = boundedInt(exchange.query("offset"), 0, 0, 100_000);
        int limit = boundedInt(exchange.query("limit"), 50, 1, MAX_PAGE);
        List<String> entries = new ArrayList<>();
        for (int i = offset; i < Math.min(rows.size(), offset + limit); i++) {
            HttpRequestResponse item = rows.get(i);
            boolean hasResponse = item.hasResponse();
            entries.add(Json.object(
                    Json.pair("entry_id", Json.quote(siteMapEntryId(item))),
                    Json.pair("url", Json.quote(Redaction.url(item.request().url()))),
                    Json.pair("method", Json.quote(item.request().method())),
                    Json.pair("status", Json.number(hasResponse ? item.response().statusCode() : 0)),
                    Json.pair("response_bytes", Json.number(hasResponse ? item.response().body().length() : 0)),
                    Json.pair("content_type", Json.quote(hasResponse ? safe(item.response().headerValue("Content-Type")) : ""))));
        }
        exchange.send(200, Json.object(
                Json.pair("ok", "true"), Json.pair("total", Json.number(rows.size())),
                Json.pair("offset", Json.number(offset)), Json.pair("limit", Json.number(limit)),
                Json.pair("entries", Json.array(entries))));
    }

    private void issues(BridgeServer.Exchange exchange) throws IOException {
        requireGet(exchange);
        String host = requireHost(exchange);
        List<AuditIssue> rows = new ArrayList<>();
        for (AuditIssue item : api.siteMap().issues()) {
            if (matchesHost(item.baseUrl(), host)) rows.add(item);
        }
        rows.sort(Comparator.comparing((AuditIssue item) -> Redaction.url(item.baseUrl()), String.CASE_INSENSITIVE_ORDER));
        int offset = boundedInt(exchange.query("offset"), 0, 0, 100_000);
        int limit = boundedInt(exchange.query("limit"), 50, 1, MAX_PAGE);
        List<String> entries = new ArrayList<>();
        for (int i = offset; i < Math.min(rows.size(), offset + limit); i++) {
            AuditIssue item = rows.get(i);
            entries.add(Json.object(
                    Json.pair("name", Json.quote(safe(item.name()))),
                    Json.pair("severity", Json.quote(String.valueOf(item.severity()))),
                    Json.pair("confidence", Json.quote(String.valueOf(item.confidence()))),
                    Json.pair("base_url", Json.quote(Redaction.url(item.baseUrl()))),
                    Json.pair("detail", Json.quote(limitUtf8(Redaction.text(safe(item.detail())), 4 * 1024)))));
        }
        exchange.send(200, Json.object(
                Json.pair("ok", "true"), Json.pair("total", Json.number(rows.size())),
                Json.pair("offset", Json.number(offset)), Json.pair("limit", Json.number(limit)),
                Json.pair("issues", Json.array(entries))));
    }

    private void webSocketHistory(BridgeServer.Exchange exchange) throws IOException {
        requireGet(exchange);
        String host = requireHost(exchange);
        List<ProxyWebSocketMessage> rows = new ArrayList<>();
        for (ProxyWebSocketMessage item : api.proxy().webSocketHistory()) {
            if (matchesHost(item.upgradeRequest().url(), host)) rows.add(item);
        }
        int offset = boundedInt(exchange.query("offset"), 0, 0, 100_000);
        int limit = boundedInt(exchange.query("limit"), 30, 1, MAX_PAGE);
        List<String> entries = new ArrayList<>();
        for (int i = offset; i < Math.min(rows.size(), offset + limit); i++) {
            ProxyWebSocketMessage item = rows.get(i);
            Direction direction = item.direction();
            entries.add(Json.object(
                    Json.pair("web_socket_id", Json.number(item.webSocketId())),
                    Json.pair("direction", Json.quote(String.valueOf(direction))),
                    Json.pair("url", Json.quote(Redaction.url(item.upgradeRequest().url()))),
                    Json.pair("payload_bytes", Json.number(item.payload().length())),
                    Json.pair("preview", Json.quote(limitUtf8(Redaction.text(item.payload().toString()), 512))),
                    Json.pair("timestamp", Json.number(item.time().withZoneSameInstant(ZoneOffset.UTC).toInstant().toEpochMilli()))));
        }
        exchange.send(200, Json.object(
                Json.pair("ok", "true"), Json.pair("total", Json.number(rows.size())),
                Json.pair("offset", Json.number(offset)), Json.pair("limit", Json.number(limit)),
                Json.pair("entries", Json.array(entries))));
    }

    private void scope(BridgeServer.Exchange exchange) throws IOException {
        requireGet(exchange);
        String raw = safe(exchange.query("url"));
        if (!raw.startsWith("http://") && !raw.startsWith("https://")) throw new BadRequest("url must be absolute http(s)");
        exchange.send(200, Json.object(
                Json.pair("ok", "true"),
                Json.pair("url", Json.quote(Redaction.url(raw))),
                Json.pair("in_scope", Json.bool(api.scope().isInScope(raw)))));
    }

    private void intercept(BridgeServer.Exchange exchange) throws IOException {
        if ("GET".equals(exchange.method())) {
            exchange.send(200, Json.object(Json.pair("ok", "true"), Json.pair("enabled", Json.bool(api.proxy().isInterceptEnabled()))));
            return;
        }
        requirePost(exchange);
        String enabled = safe(exchange.query("enabled"));
        if (!enabled.equals("true") && !enabled.equals("false")) throw new BadRequest("enabled must be true or false");
        if ("true".equals(enabled)) api.proxy().enableIntercept();
        else api.proxy().disableIntercept();
        exchange.send(200, Json.object(Json.pair("ok", "true"), Json.pair("enabled", Json.bool(api.proxy().isInterceptEnabled()))));
    }

    // ---------------------------------------------------------------- utility routes

    private void decoder(BridgeServer.Exchange exchange) throws IOException {
        requirePost(exchange);
        String operation = safe(exchange.query("op")).toLowerCase(Locale.ROOT);
        String value = exchange.bodyText();
        if (value.length() > 256 * 1024) throw new BadRequest("value exceeds the decoder limit");
        String result;
        try {
            result = switch (operation) {
                case "base64_encode" -> Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
                case "base64_decode" -> new String(Base64.getDecoder().decode(value.trim()), StandardCharsets.UTF_8);
                case "url_encode" -> java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
                case "url_decode" -> java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
                case "hex_encode" -> HexFormat.of().formatHex(value.getBytes(StandardCharsets.UTF_8));
                case "hex_decode" -> new String(HexFormat.of().parseHex(value.replaceAll("\\s+", "")), StandardCharsets.UTF_8);
                case "html_encode" -> value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
                case "html_decode" -> value.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'").replace("&amp;", "&");
                case "sha256" -> HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
                case "uuid" -> java.util.UUID.randomUUID().toString();
                default -> throw new BadRequest("unsupported decoder operation: " + operation);
            };
        } catch (IllegalArgumentException invalid) {
            throw new BadRequest("decoder input is not valid for " + operation);
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new BadRequest("sha256 is unavailable");
        }
        exchange.send(200, Json.object(
                Json.pair("ok", "true"),
                Json.pair("operation", Json.quote(operation)),
                Json.pair("input_bytes", Json.number(value.getBytes(StandardCharsets.UTF_8).length)),
                Json.pair("result", Json.quote(limitUtf8(result, 64 * 1024)))));
    }

    // ---------------------------------------------------------------- action routes

    private void send(BridgeServer.Exchange exchange) throws IOException {
        requirePost(exchange);
        String host = requireHost(exchange);
        String rawUrl = safe(exchange.query("url"));
        String method = requireMethod(exchange);
        URI uri = requireSameHost(rawUrl, host);
        HttpRequest request = buildRequest(uri, method, exchange.queryAll("h"), exchange.bodyText());
        HttpRequest prepared = Rules.engine(api).apply(request);
        if (prepared == null) {
            exchange.send(200, Json.object(
                    Json.pair("ok", "true"),
                    Json.pair("blocked", "true"),
                    Json.pair("url", Json.quote(Redaction.url(rawUrl))),
                    Json.pair("reason", Json.quote("a rewrite rule blocked this request"))));
            return;
        }
        request = prepared;
        boolean follow = "always".equalsIgnoreCase(safe(exchange.query("redirect")));
        long started = System.nanoTime();
        HttpRequestResponse result = api.http().sendRequest(request, RequestOptions.requestOptions()
                .withRedirectionMode(follow ? RedirectionMode.ALWAYS : RedirectionMode.NEVER));
        long elapsed = (System.nanoTime() - started) / 1_000_000;
        if (result == null || !result.hasResponse()) {
            exchange.send(502, Json.error("Burp did not return a response"));
            return;
        }
        HttpResponse rewritten = Rules.engine(api).applyResponse(request, result.response());
        String body = safe(rewritten.bodyToString());
        List<String> headers = new ArrayList<>();
        int headerCount = 0;
        for (HttpHeader header : rewritten.headers()) {
            if (headerCount++ >= MAX_RESPONSE_HEADERS) break;
            headers.add(Json.object(Json.pair("name", Json.quote(safe(header.name()))), Json.pair("value", Json.quote(Redaction.text(safe(header.value()))))));
        }
        exchange.send(200, Json.object(
                Json.pair("ok", "true"),
                Json.pair("url", Json.quote(Redaction.url(rawUrl))),
                Json.pair("method", Json.quote(method)),
                Json.pair("status", Json.number(rewritten.statusCode())),
                Json.pair("elapsed_ms", Json.number(elapsed)),
                Json.pair("response_bytes", Json.number(rewritten.body().length())),
                Json.pair("content_type", Json.quote(safe(rewritten.headerValue("Content-Type")))),
                Json.pair("headers", Json.array(headers)),
                Json.pair("body_preview", Json.quote(limitUtf8(Redaction.text(body), MAX_BODY_PREVIEW))),
                Json.pair("truncated", Json.bool(body.getBytes(StandardCharsets.UTF_8).length > MAX_BODY_PREVIEW)),
                Json.pair("redacted", "true")));
    }

    private void repeater(BridgeServer.Exchange exchange) throws IOException {
        requirePost(exchange);
        String host = requireHost(exchange);
        String rawUrl = safe(exchange.query("url"));
        if (rawUrl.isEmpty()) throw new BadRequest("url is required");
        URI uri = requireSameHost(rawUrl, host);
        HttpRequest request = buildRequest(uri, requireMethod(exchange), exchange.queryAll("h"), exchange.bodyText());
        String tab = safe(exchange.query("tab"));
        if (tab.isEmpty()) api.repeater().sendToRepeater(request);
        else api.repeater().sendToRepeater(request, tab.substring(0, Math.min(64, tab.length())));
        exchange.send(200, Json.object(
                Json.pair("ok", "true"), Json.pair("url", Json.quote(Redaction.url(rawUrl))),
                Json.pair("method", Json.quote(request.method())),
                Json.pair("tab", Json.quote(tab.isEmpty() ? "auto" : tab))));
    }

    private void organizer(BridgeServer.Exchange exchange) throws IOException {
        requirePost(exchange);
        String host = requireHost(exchange);
        String rawUrl = safe(exchange.query("url"));
        if (rawUrl.isEmpty()) throw new BadRequest("url is required");
        URI uri = requireSameHost(rawUrl, host);
        HttpRequest request = buildRequest(uri, requireMethod(exchange), exchange.queryAll("h"), exchange.bodyText());
        api.organizer().sendToOrganizer(request);
        exchange.send(200, Json.object(
                Json.pair("ok", "true"), Json.pair("url", Json.quote(Redaction.url(rawUrl))),
                Json.pair("method", Json.quote(request.method()))));
    }

    // ---------------------------------------------------------------- collaborator routes

    private CollaboratorClient collaborator() {
        if (collaborator == null) collaborator = api.collaborator().createClient();
        return collaborator;
    }

    private void collaboratorGenerate(BridgeServer.Exchange exchange) throws IOException {
        requirePost(exchange);
        CollaboratorPayload payload = collaborator().generatePayload();
        exchange.send(200, Json.object(
                Json.pair("ok", "true"),
                Json.pair("payload", Json.quote(payload.toString())),
                Json.pair("id", Json.quote(String.valueOf(payload.id())))));
    }

    private void collaboratorPoll(BridgeServer.Exchange exchange) throws IOException {
        requireGet(exchange);
        int limit = boundedInt(exchange.query("limit"), 30, 1, MAX_PAGE);
        List<Interaction> rows = new ArrayList<>(collaborator().getAllInteractions());
        rows.sort(Comparator.comparing((Interaction item) -> item.timeStamp()).reversed());
        List<String> entries = new ArrayList<>();
        for (int i = 0; i < Math.min(rows.size(), limit); i++) {
            Interaction item = rows.get(i);
            String protocol = item.httpDetails().isPresent() ? "http" : item.dnsDetails().isPresent() ? "dns" : "smtp";
            String summary = item.httpDetails().isPresent()
                    ? safe(item.httpDetails().get().requestResponse().request().url())
                    : item.dnsDetails().isPresent() ? item.dnsDetails().get().query().toString() : "";
            entries.add(Json.object(
                    Json.pair("id", Json.quote(String.valueOf(item.id()))),
                    Json.pair("type", Json.quote(String.valueOf(item.type()))),
                    Json.pair("protocol", Json.quote(protocol)),
                    Json.pair("timestamp", Json.number(item.timeStamp().withZoneSameInstant(ZoneOffset.UTC).toInstant().toEpochMilli())),
                    Json.pair("client_ip", Json.quote(String.valueOf(item.clientIp()))),
                    Json.pair("client_port", Json.number(item.clientPort())),
                    Json.pair("summary", Json.quote(limitUtf8(Redaction.url(summary), 512)))));
        }
        exchange.send(200, Json.object(
                Json.pair("ok", "true"), Json.pair("total", Json.number(rows.size())),
                Json.pair("interactions", Json.array(entries))));
    }

    // ---------------------------------------------------------------- scanner routes

    private void scanAudit(BridgeServer.Exchange exchange) throws IOException {
        requirePost(exchange);
        String host = requireHost(exchange);
        String rawUrl = safe(exchange.query("url"));
        if (rawUrl.isEmpty()) throw new BadRequest("url is required");
        URI uri = requireSameHost(rawUrl, host);
        boolean active = "active".equalsIgnoreCase(safe(exchange.query("mode")));
        HttpRequest request = buildRequest(uri, "GET", exchange.queryAll("h"), "");
        Audit audit = api.scanner().startAudit(AuditConfiguration.auditConfiguration(
                active ? BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS : BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS));
        audit.addRequest(request);
        String id = "audit-" + shortHash(rawUrl + System.nanoTime());
        audits.put(id, audit);
        auditHosts.put(id, host);
        exchange.send(200, Json.object(
                Json.pair("ok", "true"),
                Json.pair("audit_id", Json.quote(id)),
                Json.pair("mode", Json.quote(active ? "active" : "passive")),
                Json.pair("url", Json.quote(Redaction.url(rawUrl))),
                Json.pair("status", Json.quote(safe(audit.statusMessage()))),
                Json.pair("insertion_points", Json.number(audit.insertionPointCount())),
                Json.pair("requests", Json.number(audit.requestCount()))));
    }

    private void scanStatus(BridgeServer.Exchange exchange) throws IOException {
        requireGet(exchange);
        String only = safe(exchange.query("id"));
        List<String> entries = new ArrayList<>();
        for (Map.Entry<String, Audit> item : audits.entrySet()) {
            if (!only.isEmpty() && !item.getKey().equals(only)) continue;
            Audit audit = item.getValue();
            List<String> issues = new ArrayList<>();
            List<AuditIssue> found = audit.issues();
            int count = 0;
            for (AuditIssue issue : found) {
                if (count++ >= 50) break;
                issues.add(Json.object(
                        Json.pair("name", Json.quote(safe(issue.name()))),
                        Json.pair("severity", Json.quote(String.valueOf(issue.severity()))),
                        Json.pair("confidence", Json.quote(String.valueOf(issue.confidence()))),
                        Json.pair("base_url", Json.quote(Redaction.url(issue.baseUrl())))));
            }
            entries.add(Json.object(
                    Json.pair("audit_id", Json.quote(item.getKey())),
                    Json.pair("host", Json.quote(safe(auditHosts.get(item.getKey())))),
                    Json.pair("status", Json.quote(safe(audit.statusMessage()))),
                    Json.pair("requests", Json.number(audit.requestCount())),
                    Json.pair("errors", Json.number(audit.errorCount())),
                    Json.pair("issue_count", Json.number(found.size())),
                    Json.pair("issues", Json.array(issues))));
        }
        exchange.send(200, Json.object(Json.pair("ok", "true"), Json.pair("audits", Json.array(entries))));
    }

    private void scanStop(BridgeServer.Exchange exchange) throws IOException {
        requirePost(exchange);
        String id = safe(exchange.query("id"));
        Audit audit = audits.remove(id);
        if (audit == null) throw new BadRequest("unknown audit_id");
        auditHosts.remove(id);
        audit.delete();
        exchange.send(200, Json.object(Json.pair("ok", "true"), Json.pair("audit_id", Json.quote(id)), Json.pair("stopped", "true")));
    }

    // ---------------------------------------------------------------- helpers

    private List<HttpRequestResponse> siteMapRows(String host) {
        return new ArrayList<>(api.siteMap().requestResponses(node -> matchesHost(node.url(), host)));
    }

    static void requireGet(BridgeServer.Exchange exchange) throws BadRequest {
        if (!"GET".equals(exchange.method())) throw new BadRequest("GET required");
    }

    static void requirePost(BridgeServer.Exchange exchange) throws BadRequest {
        if (!"POST".equals(exchange.method())) throw new BadRequest("POST required");
    }

    static String requireHost(BridgeServer.Exchange exchange) throws BadRequest {
        String host = normalizedHost(exchange.query("host"));
        if (host.isEmpty()) throw new BadRequest("host filter is required");
        return host;
    }

    private String requireMethod(BridgeServer.Exchange exchange) throws BadRequest {
        String method = safe(exchange.query("method")).toUpperCase(Locale.ROOT);
        if (method.isEmpty()) method = "GET";
        if (!ALLOWED_METHODS.contains(method)) throw new BadRequest("unsupported method: " + method);
        return method;
    }

    private URI requireSameHost(String rawUrl, String host) throws BadRequest {
        URI uri;
        try {
            uri = URI.create(rawUrl.trim());
        } catch (RuntimeException invalid) {
            throw new BadRequest("url is not a valid absolute URL");
        }
        if (uri.getScheme() == null || !(uri.getScheme().equalsIgnoreCase("http") || uri.getScheme().equalsIgnoreCase("https"))) {
            throw new BadRequest("url must be absolute http(s)");
        }
        if (uri.getHost() == null || !uri.getHost().equalsIgnoreCase(host)) {
            throw new BadRequest("url host must match the session target host");
        }
        return uri;
    }

    private HttpRequest buildRequest(URI uri, String method, List<String> headerLines, String body) {
        boolean secure = "https".equalsIgnoreCase(uri.getScheme());
        int port = uri.getPort() > 0 ? uri.getPort() : secure ? 443 : 80;
        HttpService service = HttpService.httpService(uri.getHost(), port, secure);
        String path = (uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath())
                + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
        StringBuilder message = new StringBuilder();
        message.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
        message.append("Host: ").append(uri.getHost());
        if (uri.getPort() > 0) message.append(':').append(uri.getPort());
        message.append("\r\n");
        boolean hostHeaderSeen = false;
        for (String line : headerLines) {
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            String name = line.substring(0, colon).trim();
            String value = line.substring(colon + 1).trim();
            if (name.isEmpty() || name.contains("\r") || name.contains("\n")) continue;
            if (name.equalsIgnoreCase("host")) { hostHeaderSeen = true; continue; }
            if (name.equalsIgnoreCase("content-length")) continue;
            message.append(name).append(": ").append(value.replace("\r", "").replace("\n", " ")).append("\r\n");
        }
        if (!hostHeaderSeen) { /* Host is written above. */ }
        byte[] payload = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        if (payload.length > 0) message.append("Content-Length: ").append(payload.length).append("\r\n");
        message.append("\r\n");
        if (payload.length > 0) message.append(body);
        return HttpRequest.httpRequest(service, message.toString());
    }

    private static String proxyEntryId(ProxyHttpRequestResponse item) {
        return "proxy:" + shortHash(item.finalRequest().toString() + "\n" + item.time());
    }

    private static String siteMapEntryId(HttpRequestResponse item) {
        return "sitemap:" + shortHash(item.request().toString() + "\n" + (item.hasResponse() ? item.response().toString() : ""));
    }

    private static String shortHash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash, 0, 8);
        } catch (Exception error) {
            return Integer.toHexString(value.hashCode());
        }
    }

    static String normalizedHost(String value) {
        String raw = value == null ? "" : value.trim();
        if (raw.isEmpty()) return "";
        try {
            String parsed = URI.create(raw).getHost();
            if (parsed != null) return parsed.toLowerCase(Locale.ROOT);
        } catch (RuntimeException ignored) {
            // A bare hostname is not a URI with an authority, so fall through to manual parsing.
        }
        String cleaned = raw.replaceFirst("^[a-zA-Z][a-zA-Z0-9+.-]*://", "").replaceFirst("^//", "");
        int slash = cleaned.indexOf('/');
        if (slash >= 0) cleaned = cleaned.substring(0, slash);
        int at = cleaned.lastIndexOf('@');
        if (at >= 0) cleaned = cleaned.substring(at + 1);
        if (cleaned.startsWith("[")) {
            int end = cleaned.indexOf(']');
            cleaned = end > 0 ? cleaned.substring(1, end) : "";
        } else {
            int colon = cleaned.indexOf(':');
            if (colon > 0) cleaned = cleaned.substring(0, colon);
        }
        cleaned = cleaned.toLowerCase(Locale.ROOT);
        return cleaned.matches("[a-z0-9]([a-z0-9.-]*[a-z0-9])?") ? cleaned : "";
    }

    static boolean matchesHost(String rawUrl, String host) {
        try {
            return host.equalsIgnoreCase(URI.create(rawUrl).getHost());
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private static int boundedInt(String raw, int fallback, int min, int max) {
        if (raw == null) return fallback;
        try {
            return Math.max(min, Math.min(max, Integer.parseInt(raw.trim())));
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    static String safe(String value) {
        return value == null ? "" : value;
    }

    static String limitUtf8(String value, int maxBytes) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= maxBytes) return value;
        int end = maxBytes;
        while (end > 0 && (bytes[end] & 0xC0) == 0x80) end--;
        return new String(bytes, 0, end, StandardCharsets.UTF_8) + "\n[truncated]";
    }

    /** Runtime failure that maps to a 400 with a message the agent can act on. */
    static final class BadRequest extends RuntimeException {
        private static final long serialVersionUID = 1L;
        BadRequest(String message) { super(message); }
    }
}