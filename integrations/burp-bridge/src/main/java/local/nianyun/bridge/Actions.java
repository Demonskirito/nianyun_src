package local.nianyun.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.ShutdownOptions;
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.ReportFormat;
import burp.api.montoya.scanner.ScanTask;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.bchecks.BCheckImportResult;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Full-surface endpoints: everything Burp exposes programmatically that the read/audit routes in
 * {@link Routes} do not cover — Burp control (task engine, options, shutdown, self-unload, logging),
 * Intruder-style attacks, reply analysis, conversion utilities, cookie jar, sitemap writes, scope
 * edits, crawls, per-audit issues and report generation.
 *
 * These are deliberately high-risk: the operator runs the bridge against its own authorised targets,
 * so nothing here is disabled. The client still records every call in the evidence ledger.
 */
final class Actions {

    private static final int MAX_JSON_BYTES = 256 * 1024;
    private static final int MAX_BATCH = 50;
    private static final int MAX_DIFF_LINES = 600;

    private final MontoyaApi api;
    private final Engine engine;
    private final Convert convert;
    private final Map<String, ScanTask> crawls = new ConcurrentHashMap<>();

    Actions(MontoyaApi api) {
        this.api = api;
        this.engine = new Engine(api);
        this.convert = new Convert(api);
    }

    // ---------------------------------------------------------------- info & Burp control

    void info(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requireGet(exchange);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("name", "nianyun-burp-bridge");
        out.put("bridge_version", 3);
        out.put("burp_version", String.valueOf(api.burpSuite().version()));
        out.put("project", String.valueOf(api.project().name()));
        out.put("intercept", api.proxy().isInterceptEnabled());
        out.put("task_engine", api.burpSuite().taskExecutionEngine().getState().name());
        out.put("command_line_arguments", api.burpSuite().commandLineArguments());
        out.put("capabilities", capabilities());
        exchange.send(200, Json.write(out));
    }

    void optionsExport(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requireGet(exchange);
        boolean user = "user".equalsIgnoreCase(Routes.safe(exchange.query("scope")));
        String json = user ? api.burpSuite().exportUserOptionsAsJson() : api.burpSuite().exportProjectOptionsAsJson();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("scope", user ? "user" : "project");
        out.put("options", Routes.limitUtf8(json == null ? "" : json, MAX_JSON_BYTES));
        out.put("truncated", json != null && json.getBytes(StandardCharsets.UTF_8).length > MAX_JSON_BYTES);
        exchange.send(200, Json.write(out));
    }

    void control(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requirePost(exchange);
        Map<String, Object> body = jsonBody(exchange);
        String action = str(body.get("action")).toLowerCase(Locale.ROOT);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("action", action);
        switch (action) {
            case "task_engine" -> {
                String state = str(body.get("state")).toUpperCase(Locale.ROOT);
                if (!state.isEmpty()) {
                    api.burpSuite().taskExecutionEngine().setState(TaskExecutionEngineState.valueOf(state));
                }
                out.put("state", api.burpSuite().taskExecutionEngine().getState().name());
            }
            case "options_import" -> {
                String json = str(body.get("json"));
                if (json.isBlank()) throw new Routes.BadRequest("json is required");
                boolean user = "user".equalsIgnoreCase(str(body.get("scope")));
                if (user) api.burpSuite().importUserOptionsFromJson(json);
                else api.burpSuite().importProjectOptionsFromJson(json);
                out.put("scope", user ? "user" : "project");
                out.put("imported", true);
            }
            case "log" -> {
                String level = str(body.get("level")).toLowerCase(Locale.ROOT);
                String message = str(body.get("message"));
                switch (level) {
                    case "debug" -> api.logging().raiseDebugEvent(message);
                    case "error" -> api.logging().raiseErrorEvent(message);
                    case "critical" -> api.logging().raiseCriticalEvent(message);
                    default -> api.logging().raiseInfoEvent(message);
                }
                out.put("level", level.isEmpty() ? "info" : level);
            }
            case "decoder_send" -> {
                api.decoder().sendToDecoder(ByteArray.byteArray(str(body.get("value")).getBytes(StandardCharsets.UTF_8)));
                out.put("sent", true);
            }
            case "shutdown" -> {
                api.logging().logToOutput("Nianyun bridge: shutdown requested through the bridge.");
                api.burpSuite().shutdown(ShutdownOptions.PROMPT_USER);
                out.put("shutdown", "requested");
            }
            case "unload" -> {
                api.logging().logToOutput("Nianyun bridge: unloading the bridge extension on request.");
                out.put("unload", "requested");
                exchange.send(200, Json.write(out));
                api.extension().unload();
                return;
            }
            default -> throw new Routes.BadRequest("control action must be task_engine, options_import, log,"
                    + " decoder_send, shutdown or unload");
        }
        exchange.send(200, Json.write(out));
    }

    void cookies(BridgeServer.Exchange exchange) throws java.io.IOException {
        if ("POST".equals(exchange.method())) {
            Map<String, Object> body = jsonBody(exchange);
            String name = str(body.get("name"));
            String value = str(body.get("value"));
            String domain = str(body.get("domain"));
            String path = str(body.get("path"));
            if (path.isEmpty()) path = "/";
            if (name.isEmpty() || domain.isEmpty()) throw new Routes.BadRequest("name and domain are required");
            api.http().cookieJar().setCookie(name, value, domain, path, ZonedDateTime.now().plusDays(1));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", true);
            out.put("set", true);
            out.put("name", name);
            out.put("domain", domain);
            out.put("path", path);
            exchange.send(200, Json.write(out));
            return;
        }
        Routes.requireGet(exchange);
        List<Object> rows = new ArrayList<>();
        for (Cookie cookie : api.http().cookieJar().cookies()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", cookie.name());
            row.put("domain", cookie.domain());
            row.put("path", cookie.path());
            row.put("expires", cookie.expiration().map(Object::toString).orElse(""));
            rows.add(row);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("total", rows.size());
        // Cookie values stay inside Burp; only names and scope are returned.
        out.put("cookies", rows);
        out.put("values_redacted", true);
        exchange.send(200, Json.write(out));
    }

    void storage(BridgeServer.Exchange exchange) throws java.io.IOException {
        var store = api.persistence().extensionData();
        Map<String, Object> out = new LinkedHashMap<>();
        if ("GET".equals(exchange.method())) {
            String key = Routes.safe(exchange.query("key"));
            if (key.isEmpty()) {
                out.put("ok", true);
                out.put("keys", new ArrayList<>(store.stringKeys()));
            } else {
                out.put("ok", true);
                out.put("key", key);
                out.put("value", Routes.limitUtf8(store.getString(key), MAX_JSON_BYTES));
            }
            exchange.send(200, Json.write(out));
            return;
        }
        Routes.requirePost(exchange);
        Map<String, Object> body = jsonBody(exchange);
        String action = str(body.get("action")).toLowerCase(Locale.ROOT);
        String key = str(body.get("key"));
        if (key.isEmpty()) throw new Routes.BadRequest("key is required");
        if (action.equals("delete")) {
            store.deleteString(key);
            out.put("deleted", true);
        } else {
            store.setString(key, str(body.get("value")));
            out.put("stored", true);
        }
        out.put("ok", true);
        out.put("key", key);
        exchange.send(200, Json.write(out));
    }

    // ---------------------------------------------------------------- site map & scope

    void siteMapIssues(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requireGet(exchange);
        String host = Routes.requireHost(exchange);
        List<Object> rows = new ArrayList<>();
        for (AuditIssue issue : api.siteMap().issues(node -> Routes.matchesHost(node.url(), host))) {
            rows.add(issueRow(issue));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("total", rows.size());
        out.put("issues", rows);
        out.put("unverified", true);
        exchange.send(200, Json.write(out));
    }

    void siteMapAdd(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requirePost(exchange);
        Map<String, Object> body = jsonBody(exchange);
        HttpRequest request = requestFrom(body, exchange);
        HttpRequestResponse rr = api.http().sendRequest(request,
                RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.NEVER));
        if (rr != null) api.siteMap().add(rr);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("added", true);
        out.put("url", Redaction.url(request.url()));
        out.put("status", rr != null && rr.hasResponse() ? rr.response().statusCode() : 0);
        exchange.send(200, Json.write(out));
    }

    void scopeEdit(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requirePost(exchange);
        Map<String, Object> body = jsonBody(exchange);
        String action = str(body.get("action")).toLowerCase(Locale.ROOT);
        String url = str(body.get("url"));
        if (url.isBlank()) throw new Routes.BadRequest("url is required");
        if (action.equals("exclude")) api.scope().excludeFromScope(url);
        else if (action.equals("include")) api.scope().includeInScope(url);
        else throw new Routes.BadRequest("action must be include or exclude");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("action", action);
        out.put("url", url);
        out.put("in_scope", api.scope().isInScope(url));
        exchange.send(200, Json.write(out));
    }

    // ---------------------------------------------------------------- HTTP batch & crawls

    void sendBatch(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requirePost(exchange);
        Map<String, Object> body = jsonBody(exchange);
        Object raw = body.get("requests");
        if (!(raw instanceof List<?> list) || list.isEmpty()) throw new Routes.BadRequest("requests must be a non-empty array");
        if (list.size() > MAX_BATCH) throw new Routes.BadRequest("at most " + MAX_BATCH + " requests per batch");
        List<HttpRequest> requests = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new Routes.BadRequest("each request must be an object");
            @SuppressWarnings("unchecked")
            Map<String, Object> spec = (Map<String, Object>) map;
            requests.add(requestFrom(spec, exchange));
        }
        Rules rules = Rules.engine(api);
        List<HttpRequest> allowed = new ArrayList<>();
        List<Object> blocked = new ArrayList<>();
        for (int i = 0; i < requests.size(); i++) {
            HttpRequest prepared = rules.apply(requests.get(i));
            if (prepared == null) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("index", i);
                row.put("url", Redaction.url(requests.get(i).url()));
                row.put("status", 0);
                row.put("blocked", true);
                blocked.add(row);
                continue;
            }
            allowed.add(prepared);
        }
        List<Object> rows = new ArrayList<>(blocked);
        List<HttpRequestResponse> responses = allowed.isEmpty() ? List.of() : api.http().sendRequests(allowed);
        for (int i = 0; i < responses.size(); i++) {
            HttpRequestResponse rr = responses.get(i);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("index", i);
            HttpRequest sent = allowed.get(i);
            row.put("url", Redaction.url(sent.url()));
            HttpResponse batched = rr != null && rr.hasResponse() ? rules.applyResponse(sent, rr.response()) : null;
            row.put("status", batched == null ? 0 : batched.statusCode());
            row.put("length", batched == null ? 0 : batched.body().length());
            if (rr != null && rr.hasResponse()) {
                row.put("preview", Routes.limitUtf8(Redaction.text(batched.bodyToString()), 4096));
            }
            rows.add(row);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("sent", rows.size());
        out.put("responses", rows);
        exchange.send(200, Json.write(out));
    }

    void crawl(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requirePost(exchange);
        Map<String, Object> body = jsonBody(exchange);
        List<String> seeds = new ArrayList<>();
        Object raw = body.get("seeds");
        if (raw instanceof List<?> list) for (Object item : list) seeds.add(str(item));
        else {
            String single = str(body.get("url"));
            if (!single.isBlank()) seeds.add(single);
        }
        if (seeds.isEmpty()) throw new Routes.BadRequest("seeds or url is required");
        ScanTask task;
        String status;
        try {
            task = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(seeds.toArray(new String[0])));
            status = task.statusMessage();
        } catch (Throwable error) {
            // Burp refuses crawls for out-of-scope or unlicensed targets; surface the reason.
            throw new Routes.BadRequest("Burp refused the crawl: " + error.getClass().getSimpleName()
                    + (error.getMessage() == null ? "" : " - " + error.getMessage()));
        }
        String id = "crawl-" + Integer.toHexString(System.identityHashCode(task));
        crawls.put(id, task);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("crawl_id", id);
        out.put("seeds", seeds);
        out.put("status", status);
        exchange.send(200, Json.write(out));
    }

    void crawlStatus(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requireGet(exchange);
        String id = Routes.safe(exchange.query("id"));
        List<Object> rows = new ArrayList<>();
        for (Map.Entry<String, ScanTask> entry : crawls.entrySet()) {
            if (!id.isEmpty() && !entry.getKey().equals(id)) continue;
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("crawl_id", entry.getKey());
            try {
                row.put("requests", entry.getValue().requestCount());
                row.put("errors", entry.getValue().errorCount());
                row.put("status", entry.getValue().statusMessage());
            } catch (Throwable error) {
                row.put("error", error.getClass().getSimpleName());
            }
            rows.add(row);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("total", rows.size());
        out.put("crawls", rows);
        exchange.send(200, Json.write(out));
    }

    // ---------------------------------------------------------------- scanner detail

    void scanIssues(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requireGet(exchange);
        String id = Routes.safe(exchange.query("id"));
        List<Object> rows = new ArrayList<>();
        for (Map.Entry<String, Audit> entry : Routes.auditsOf().entrySet()) {
            if (!id.isEmpty() && !entry.getKey().equals(id)) continue;
            for (AuditIssue issue : entry.getValue().issues()) {
                Map<String, Object> row = issueRow(issue);
                row.put("audit_id", entry.getKey());
                rows.add(row);
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("total", rows.size());
        out.put("issues", rows);
        out.put("unverified", true);
        exchange.send(200, Json.write(out));
    }

    void scanReport(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requirePost(exchange);
        Map<String, Object> body = jsonBody(exchange);
        String id = str(body.get("audit_id"));
        String format = str(body.get("format")).toUpperCase(Locale.ROOT);
        if (format.isEmpty()) format = "HTML";
        String path = str(body.get("path"));
        if (path.isBlank()) throw new Routes.BadRequest("path is required (a file path on the Burp host)");
        List<AuditIssue> issues = new ArrayList<>();
        var audits = Routes.auditsOf();
        if (id.isEmpty()) {
            for (Audit audit : audits.values()) issues.addAll(audit.issues());
        } else {
            Audit audit = audits.get(id);
            if (audit == null) throw new Routes.BadRequest("unknown audit id: " + id);
            issues.addAll(audit.issues());
        }
        ReportFormat reportFormat = ReportFormat.valueOf(format);
        api.scanner().generateReport(issues, reportFormat, Path.of(path));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("format", reportFormat.name());
        out.put("path", path);
        out.put("issues", issues.size());
        out.put("exists", Files.exists(Path.of(path)));
        exchange.send(200, Json.write(out));
    }

    // ---------------------------------------------------------------- Intruder engine

    void intruder(BridgeServer.Exchange exchange) throws java.io.IOException {
        if ("GET".equals(exchange.method())) {
            exchange.send(200, engine.list());
            return;
        }
        Routes.requirePost(exchange);
        Map<String, Object> body = jsonBody(exchange);
        String url = str(body.get("url"));
        String host = str(body.get("host"));
        boolean secure = !str(body.get("secure")).equalsIgnoreCase("false");
        if (!url.isEmpty()) {
            URI uri = URI.create(url);
            if (host.isEmpty() && uri.getHost() != null) host = uri.getHost();
            secure = uri.getPort() == 80 ? false : !"http".equalsIgnoreCase(uri.getScheme());
        }
        if (host.isEmpty()) throw new Routes.BadRequest("host or url is required");
        String id = engine.start(body, host, secure);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("attack_id", id);
        out.put("status", "started");
        exchange.send(200, Json.write(out));
    }

    void intruderStatus(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requireGet(exchange);
        exchange.send(200, engine.status(Routes.safe(exchange.query("id"))));
    }

    void intruderStop(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requirePost(exchange);
        exchange.send(200, engine.stop(exchange.query("id")));
    }

    void intruderSend(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requirePost(exchange);
        Map<String, Object> body = jsonBody(exchange);
        HttpRequest request = requestFrom(body, exchange);
        String tab = str(body.get("tab"));
        if (tab.isBlank()) api.intruder().sendToIntruder(request);
        else api.intruder().sendToIntruder(request, tab);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("sent", true);
        out.put("url", Redaction.url(request.url()));
        out.put("tab", tab);
        exchange.send(200, Json.write(out));
    }

    // ---------------------------------------------------------------- rewrite rules

    void rules(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requirePost(exchange);
        Map<String, Object> body = jsonBody(exchange);
        Rules rules = Rules.engine(api);
        String action = str(body.get("action")).toLowerCase(Locale.ROOT);
        if (action.isEmpty()) action = "list";
        Map<String, Object> out = switch (action) {
            case "list" -> {
                List<Object> rows = new ArrayList<>();
                for (Map<String, Object> rule : rules.all()) {
                    Map<String, Object> row = new LinkedHashMap<>(rule);
                    row.put("hits", rules.hitCounters().getOrDefault(str(rule.get("id")), new java.util.concurrent.atomic.AtomicInteger()).get());
                    rows.add(row);
                }
                Map<String, Object> listed = new LinkedHashMap<>();
                listed.put("ok", true);
                listed.put("total", rows.size());
                listed.put("rules", rows);
                yield listed;
            }
            case "add" -> single("rule", rules.add(body));
            case "update" -> single("rule", rules.update(str(body.get("id")), body));
            case "remove" -> rules.remove(str(body.get("id")));
            case "clear" -> rules.clear();
            case "test" -> rules.preview(str(body.get("url")),
                    str(body.get("method")).isEmpty() ? "GET" : str(body.get("method")),
                    mapOf(body.get("headers")), str(body.get("body")));
            default -> throw new Routes.BadRequest("unknown rules action: " + action + " (list, add, update, remove, clear, test)");
        };
        exchange.send(200, Json.write(out));
    }

    // ---------------------------------------------------------------- websockets

    void websocket(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requirePost(exchange);
        Map<String, Object> body = jsonBody(exchange);
        Ws ws = Ws.sessions(api);
        String action = str(body.get("action")).toLowerCase(Locale.ROOT);
        if (action.isEmpty()) action = "list";
        Map<String, Object> out = switch (action) {
            case "open" -> ws.open(str(body.get("url")), str(body.get("protocol")), mapOf(body.get("headers")), 0);
            case "send" -> ws.send(str(body.get("session_id")), str(body.get("kind")), str(body.get("data")));
            case "messages" -> ws.messages(str(body.get("session_id")), intOf(body.get("since"), 0));
            case "close" -> ws.close(str(body.get("session_id")));
            case "list" -> ws.list();
            default -> throw new Routes.BadRequest("unknown websocket action: " + action + " (open, send, messages, close, list)");
        };
        exchange.send(200, Json.write(out));
    }

    // ---------------------------------------------------------------- bchecks

    void bchecks(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requirePost(exchange);
        Map<String, Object> body = jsonBody(exchange);
        String script = str(body.get("bcheck")).isEmpty() ? str(body.get("json")) : str(body.get("bcheck"));
        if (script.isBlank()) throw new Routes.BadRequest("bcheck is required: send the .bcheck JSON content");
        boolean selected = !"false".equalsIgnoreCase(str(body.get("selected"))) && !"0".equals(str(body.get("selected")));
        BCheckImportResult result;
        try {
            result = api.scanner().bChecks().importBCheck(script, selected);
        } catch (RuntimeException error) {
            throw new Routes.BadRequest("Burp rejected the bcheck: " + error.getClass().getSimpleName()
                    + (error.getMessage() == null ? "" : " - " + error.getMessage()));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("status", String.valueOf(result.status()));
        out.put("errors", result.importErrors() == null ? List.of() : result.importErrors());
        out.put("selected", selected);
        exchange.send(200, Json.write(out));
    }

    private static Map<String, Object> single(String key, Map<String, Object> value) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put(key, value);
        return out;
    }

    private static Map<String, Object> mapOf(Object value) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (!(value instanceof Map<?, ?> source)) return out;
        for (Map.Entry<?, ?> entry : source.entrySet()) out.put(String.valueOf(entry.getKey()), entry.getValue());
        return out;
    }

    private static int intOf(Object value, int fallback) {
        if (value instanceof Number number) return number.intValue();
        try {
            return Integer.parseInt(str(value).trim());
        } catch (NumberFormatException error) {
            return fallback;
        }
    }

    // ---------------------------------------------------------------- reply analysis

    void compare(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requirePost(exchange);
        Map<String, Object> body = jsonBody(exchange);
        String mode = str(body.get("mode")).toLowerCase(Locale.ROOT);
        if (mode.isEmpty()) mode = "diff";
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("mode", mode);
        switch (mode) {
            case "diff" -> out.putAll(diff(str(body.get("a")), str(body.get("b"))));
            case "ui" -> {
                api.comparer().sendToComparer(
                        ByteArray.byteArray(str(body.get("a")).getBytes(StandardCharsets.UTF_8)),
                        ByteArray.byteArray(str(body.get("b")).getBytes(StandardCharsets.UTF_8)));
                out.put("sent", true);
            }
            case "keywords" -> out.putAll(keywords(body));
            case "variations" -> out.putAll(variations(body));
            default -> throw new Routes.BadRequest("mode must be diff, keywords, variations or ui");
        }
        exchange.send(200, Json.write(out));
    }

    private Map<String, Object> keywords(Map<String, Object> body) {
        List<String> words = new ArrayList<>();
        if (body.get("words") instanceof List<?> list) for (Object item : list) words.add(str(item));
        if (words.isEmpty()) throw new Routes.BadRequest("words are required for keyword analysis");
        var analyzer = api.http().createResponseKeywordsAnalyzer(words);
        int sampled = sampleResponses(body, analyzer::updateWith);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sampled", sampled);
        out.put("variant_keywords", new ArrayList<>(analyzer.variantKeywords()));
        out.put("invariant_keywords", new ArrayList<>(analyzer.invariantKeywords()));
        return out;
    }

    private Map<String, Object> variations(Map<String, Object> body) {
        var analyzer = api.http().createResponseVariationsAnalyzer();
        int sampled = sampleResponses(body, analyzer::updateWith);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sampled", sampled);
        out.put("variant_attributes", new ArrayList<>(analyzer.variantAttributes()));
        out.put("invariant_attributes", new ArrayList<>(analyzer.invariantAttributes()));
        return out;
    }

    private int sampleResponses(Map<String, Object> body, java.util.function.Consumer<HttpResponse> sink) {
        List<String> urls = new ArrayList<>();
        if (body.get("urls") instanceof List<?> list) for (Object item : list) urls.add(str(item));
        int count = 0;
        for (String url : urls) {
            if (count >= 20) break;
            HttpRequest request = HttpRequest.httpRequestFromUrl(url);
            HttpRequestResponse rr = api.http().sendRequest(request,
                    RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.NEVER));
            if (rr != null && rr.hasResponse()) {
                sink.accept(rr.response());
                count++;
            }
        }
        if (count == 0) throw new Routes.BadRequest("urls must contain at least one reachable request");
        return count;
    }

    private static Map<String, Object> diff(String a, String b) {
        String[] left = a.replace("\r\n", "\n").split("\n", -1);
        String[] right = b.replace("\r\n", "\n").split("\n", -1);
        boolean truncated = left.length > MAX_DIFF_LINES || right.length > MAX_DIFF_LINES;
        if (left.length > MAX_DIFF_LINES) left = java.util.Arrays.copyOf(left, MAX_DIFF_LINES);
        if (right.length > MAX_DIFF_LINES) right = java.util.Arrays.copyOf(right, MAX_DIFF_LINES);
        int n = left.length;
        int m = right.length;
        int[][] lcs = new int[n + 1][m + 1];
        for (int i = n - 1; i >= 0; i--) {
            for (int j = m - 1; j >= 0; j--) {
                lcs[i][j] = left[i].equals(right[j]) ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
            }
        }
        List<String> hunks = new ArrayList<>();
        int added = 0;
        int removed = 0;
        int same = 0;
        int i = 0;
        int j = 0;
        while (i < n && j < m) {
            if (left[i].equals(right[j])) {
                same++;
                i++;
                j++;
            } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
                removed++;
                if (hunks.size() < 200) hunks.add("-" + left[i]);
                i++;
            } else {
                added++;
                if (hunks.size() < 200) hunks.add("+" + right[j]);
                j++;
            }
        }
        while (i < n) {
            removed++;
            if (hunks.size() < 200) hunks.add("-" + left[i]);
            i++;
        }
        while (j < m) {
            added++;
            if (hunks.size() < 200) hunks.add("+" + right[j]);
            j++;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("added", added);
        out.put("removed", removed);
        out.put("unchanged", same);
        out.put("hunks", hunks);
        out.put("truncated", truncated);
        return out;
    }

    // ---------------------------------------------------------------- conversion utilities

    void convert(BridgeServer.Exchange exchange) throws java.io.IOException {
        Routes.requirePost(exchange);
        Map<String, Object> body = jsonBody(exchange);
        Map<String, Object> out = convert.run(body);
        out.put("ok", true);
        exchange.send(200, Json.write(out));
    }

    // ---------------------------------------------------------------- helpers

    private static List<String> capabilities() {
        return List.of(
                "info", "options.export", "control", "cookies", "storage",
                "proxy.history", "proxy.entry", "ws.history", "sitemap", "sitemap.issues", "sitemap.add",
                "issues", "scope", "scope.edit", "intercept",
                "http.send", "http.send_batch", "repeater", "organizer", "decoder", "convert", "compare",
                "collab.generate", "collab.poll",
                "scan.audit", "scan.status", "scan.stop", "scan.issues", "scan.report", "crawl", "crawl.status",
                "intruder", "intruder.status", "intruder.stop", "intruder.send");
    }

    private static Map<String, Object> issueRow(AuditIssue issue) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", issue.name());
        row.put("severity", String.valueOf(issue.severity()));
        row.put("confidence", String.valueOf(issue.confidence()));
        row.put("url", Redaction.url(String.valueOf(issue.baseUrl())));
        row.put("detail", Routes.limitUtf8(Redaction.text(issue.detail()), 4096));
        row.put("remediation", Routes.limitUtf8(Redaction.text(issue.remediation()), 2048));
        row.put("request_responses", issue.requestResponses().size());
        return row;
    }

    private HttpRequest requestFrom(Map<String, Object> spec, BridgeServer.Exchange exchange) {
        String template = str(spec.get("template"));
        if (!template.isBlank()) return HttpRequest.httpRequest(template);
        String url = str(spec.get("url"));
        if (url.isBlank()) throw new Routes.BadRequest("url or template is required");
        String method = str(spec.get("method"));
        if (method.isBlank()) method = "GET";
        method = method.toUpperCase(Locale.ROOT);
        HttpRequest request = HttpRequest.httpRequestFromUrl(url).withMethod(method);
        if (spec.get("headers") instanceof Map<?, ?> headers) {
            for (Map.Entry<?, ?> entry : headers.entrySet()) {
                String name = str(entry.getKey());
                String value = str(entry.getValue()).replace("\r", "").replace("\n", " ");
                if (!name.isBlank()) request = request.withAddedHeader(name, value);
            }
        }
        String body = str(spec.get("body"));
        if (!body.isEmpty()) request = request.withBody(body);
        return request;
    }

    private Map<String, Object> jsonBody(BridgeServer.Exchange exchange) {
        String text = Routes.safe(exchange.bodyText()).trim();
        if (text.isEmpty()) throw new Routes.BadRequest("a JSON body is required");
        Object parsed;
        try {
            parsed = Json.parse(text);
        } catch (RuntimeException error) {
            throw new Routes.BadRequest("invalid JSON body: " + error.getMessage());
        }
        if (!(parsed instanceof Map<?, ?> map)) throw new Routes.BadRequest("JSON body must be an object");
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) out.put(String.valueOf(entry.getKey()), entry.getValue());
        return out;
    }

    private static String str(Object value) {
        return value == null ? "" : String.valueOf(value);
    }
}