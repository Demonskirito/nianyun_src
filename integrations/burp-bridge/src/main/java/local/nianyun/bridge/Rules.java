package local.nianyun.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Data-driven Match and Replace.
 *
 * Burp exposes rewriting only through compiled handlers, so the agent instead posts rules as data:
 * a URL regex, an optional method filter, header and body replacements for the request and for the
 * response, plus a {@code block} flag the bridge honours on its own sends. Two consumers share the
 * same rule list:
 *
 * <ul>
 *   <li>the registered {@link HttpHandler}, which rewrites everything Burp itself sends (Proxy,
 *       Repeater, Scanner, Intruder);</li>
 *   <li>the bridge send paths, because Montoya does not run {@code http.sendRequest} through
 *       registered handlers — applying the rules there keeps agent traffic consistent with the
 *       rest of Burp.</li>
 * </ul>
 *
 * Rules persist in the extension data store, so a reload keeps the operator's setup.
 */
final class Rules {

    private static final String STORAGE_KEY = "nianyun.rules";
    private static final int MAX_RULES = 200;
    private static final int MAX_BODY = 2 * 1024 * 1024;

    private static Rules instance;

    static synchronized Rules engine(MontoyaApi api) {
        if (instance == null) instance = new Rules(api);
        return instance;
    }

    private final MontoyaApi api;
    private final List<Map<String, Object>> rules = new CopyOnWriteArrayList<>();
    private final Map<String, AtomicInteger> hits = new ConcurrentHashMap<>();
    private Registration registration;

    private Rules(MontoyaApi api) {
        this.api = api;
        load();
    }

    /** Registers the Burp-wide handler once; safe to call more than once. */
    synchronized void install() {
        if (registration != null && registration.isRegistered()) return;
        registration = api.http().registerHttpHandler(new Rewriter());
    }

    synchronized void uninstall() {
        if (registration != null && registration.isRegistered()) registration.deregister();
        registration = null;
    }

    List<Map<String, Object>> all() {
        return new ArrayList<>(rules);
    }

    Map<String, Object> add(Map<String, Object> input) {
        if (rules.size() >= MAX_RULES) throw new Routes.BadRequest("rule limit reached (" + MAX_RULES + ")");
        String urlRegex = str(input.get("url_regex"));
        if (!urlRegex.isEmpty()) compile(urlRegex);
        Map<String, Object> rule = normalise(input, "rule-" + Long.toHexString(System.nanoTime()));
        rules.add(rule);
        save();
        return rule;
    }

    Map<String, Object> update(String id, Map<String, Object> input) {
        if (id.isEmpty()) throw new Routes.BadRequest("id is required");
        for (int i = 0; i < rules.size(); i++) {
            if (!id.equals(str(rules.get(i).get("id")))) continue;
            Map<String, Object> merged = new LinkedHashMap<>(rules.get(i));
            for (Map.Entry<String, Object> entry : input.entrySet()) {
                if (entry.getKey().equals("id")) continue;
                merged.put(entry.getKey(), entry.getValue());
            }
            String urlRegex = str(merged.get("url_regex"));
            if (!urlRegex.isEmpty()) compile(urlRegex);
            Map<String, Object> rule = normalise(merged, id);
            rules.set(i, rule);
            save();
            return rule;
        }
        throw new Routes.BadRequest("unknown rule id: " + id);
    }

    Map<String, Object> remove(String id) {
        if (id.isEmpty()) throw new Routes.BadRequest("id is required");
        boolean removed = rules.removeIf(rule -> id.equals(str(rule.get("id"))));
        if (!removed) throw new Routes.BadRequest("unknown rule id: " + id);
        hits.remove(id);
        save();
        return Map.of("ok", true, "removed", id, "remaining", rules.size());
    }

    Map<String, Object> clear() {
        rules.clear();
        hits.clear();
        save();
        return Map.of("ok", true, "remaining", 0);
    }

    Map<String, AtomicInteger> hitCounters() {
        return hits;
    }

    // ------------------------------------------------------------------ application

    /**
     * Applies request rules. Returns {@code null} when a rule with {@code block} matches, which the
     * bridge reports as "blocked by rule" instead of sending.
     */
    HttpRequest apply(HttpRequest request) {
        if (rules.isEmpty() || request == null) return request;
        String url = request.url();
        String method = request.method();
        HttpRequest out = request;
        for (Map<String, Object> rule : rules) {
            if (!matches(rule, url, method)) continue;
            count(rule);
            if (bool(rule.get("block"))) return null;
            out = rewriteRequest(out, rule);
        }
        return out;
    }

    HttpResponse applyResponse(HttpRequest request, HttpResponse response) {
        if (rules.isEmpty() || response == null || request == null) return response;
        String url = request.url();
        String method = request.method();
        HttpResponse out = response;
        for (Map<String, Object> rule : rules) {
            if (!matches(rule, url, method)) continue;
            out = rewriteResponse(out, rule);
        }
        return out;
    }

    boolean hasBlockingRule(String url, String method) {
        for (Map<String, Object> rule : rules) {
            if (matches(rule, url, method) && bool(rule.get("block"))) return true;
        }
        return false;
    }

    private boolean matches(Map<String, Object> rule, String url, String method) {
        if (!bool(rule.get("enabled"))) return false;
        String regex = str(rule.get("url_regex"));
        if (!regex.isEmpty()) {
            try {
                if (!Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(url).find()) return false;
            } catch (PatternSyntaxException error) {
                return false;
            }
        }
        List<String> methods = strings(rule.get("methods"));
        if (methods.isEmpty()) return true;
        for (String candidate : methods) {
            if (candidate.equalsIgnoreCase(method)) return true;
        }
        return false;
    }

    private void count(Map<String, Object> rule) {
        hits.computeIfAbsent(str(rule.get("id")), key -> new AtomicInteger()).incrementAndGet();
    }

    private static HttpRequest rewriteRequest(HttpRequest request, Map<String, Object> rule) {
        HttpRequest out = request;
        out = applyHeadersRequest(out, map(rule.get("set_headers")), strings(rule.get("remove_headers")));
        String body = out.bodyToString();
        String replaced = replaceAll(body, replacements(rule.get("body_replace")));
        if (!replaced.equals(body)) out = out.withBody(replaced);
        return out;
    }

    private static HttpResponse rewriteResponse(HttpResponse response, Map<String, Object> rule) {
        HttpResponse out = response;
        Map<String, Object> headers = map(rule.get("response_set_headers"));
        List<String> removals = strings(rule.get("response_remove_headers"));
        for (Map.Entry<String, Object> entry : headers.entrySet()) {
            out = out.hasHeader(entry.getKey())
                    ? out.withUpdatedHeader(entry.getKey(), str(entry.getValue()))
                    : out.withAddedHeader(entry.getKey(), str(entry.getValue()));
        }
        for (String header : removals) {
            if (out.hasHeader(header)) out = out.withRemovedHeader(header);
        }
        String body = out.bodyToString();
        String replaced = replaceAll(body, replacements(rule.get("response_body_replace")));
        if (!replaced.equals(body)) out = out.withBody(replaced);
        return out;
    }

    private static HttpRequest applyHeadersRequest(HttpRequest request, Map<String, Object> set, List<String> remove) {
        HttpRequest out = request;
        for (Map.Entry<String, Object> entry : set.entrySet()) {
            // withUpdatedHeader only rewrites an existing header, so a new one needs withAddedHeader.
            out = out.hasHeader(entry.getKey())
                    ? out.withUpdatedHeader(entry.getKey(), str(entry.getValue()))
                    : out.withAddedHeader(entry.getKey(), str(entry.getValue()));
        }
        for (String header : remove) {
            if (out.hasHeader(header)) out = out.withRemovedHeader(header);
        }
        return out;
    }

    private static String replaceAll(String body, List<String[]> replacements) {
        if (body == null || body.isEmpty() || body.length() > MAX_BODY || replacements.isEmpty()) return body == null ? "" : body;
        String out = body;
        for (String[] pair : replacements) {
            try {
                out = Pattern.compile(pair[0], Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(out).replaceAll(pair[1]);
            } catch (RuntimeException ignored) {
                // A broken rule must not take the whole send path down.
            }
        }
        return out;
    }

    /** Dry run used by {@code /rules action=test}: shows what the rules would do without sending. */
    Map<String, Object> preview(String url, String method, Map<String, Object> headers, String body) {
        List<String> matched = new ArrayList<>();
        Map<String, Object> outHeaders = new LinkedHashMap<>(headers);
        String outBody = body == null ? "" : body;
        boolean blocked = false;
        for (Map<String, Object> rule : rules) {
            if (!matches(rule, url, method)) continue;
            matched.add(str(rule.get("id")) + ":" + str(rule.get("name")));
            if (bool(rule.get("block"))) blocked = true;
            for (Map.Entry<String, Object> entry : map(rule.get("set_headers")).entrySet()) {
                outHeaders.put(entry.getKey(), str(entry.getValue()));
            }
            for (String header : strings(rule.get("remove_headers"))) outHeaders.remove(header);
            outBody = replaceAll(outBody, replacements(rule.get("body_replace")));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("matched", matched);
        out.put("blocked", blocked);
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("headers", outHeaders);
        request.put("body", outBody.length() > 4096 ? outBody.substring(0, 4096) : outBody);
        out.put("request", request);
        return out;
    }

    // ------------------------------------------------------------------ persistence

    private void load() {
        try {
            String stored = api.persistence().extensionData().getString(STORAGE_KEY);
            if (stored == null || stored.isBlank()) return;
            Object parsed = Json.parse(stored);
            if (!(parsed instanceof List<?> list)) return;
            for (Object item : list) {
                if (item instanceof Map<?, ?> source) {
                    Map<String, Object> rule = new LinkedHashMap<>();
                    for (Map.Entry<?, ?> entry : source.entrySet()) rule.put(String.valueOf(entry.getKey()), entry.getValue());
                    rules.add(normalise(rule, str(rule.get("id"))));
                }
            }
            api.logging().logToOutput("Nianyun Burp Bridge loaded " + rules.size() + " rewrite rule(s)");
        } catch (RuntimeException error) {
            api.logging().logToError("Nianyun Burp Bridge could not load rewrite rules: " + error);
        }
    }

    private void save() {
        try {
            api.persistence().extensionData().setString(STORAGE_KEY, Json.write(new ArrayList<>(rules)));
        } catch (RuntimeException error) {
            api.logging().logToError("Nianyun Burp Bridge could not persist rewrite rules: " + error);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static Map<String, Object> normalise(Map<String, Object> input, String fallbackId) {
        Map<String, Object> rule = new LinkedHashMap<>();
        String id = str(input.get("id"));
        rule.put("id", id.isEmpty() ? fallbackId : id);
        rule.put("name", str(input.get("name")));
        rule.put("enabled", input.get("enabled") == null || bool(input.get("enabled")));
        rule.put("url_regex", str(input.get("url_regex")));
        rule.put("methods", strings(input.get("methods")));
        rule.put("set_headers", map(input.get("set_headers")));
        rule.put("remove_headers", strings(input.get("remove_headers")));
        rule.put("body_replace", pairs(input.get("body_replace")));
        rule.put("response_set_headers", map(input.get("response_set_headers")));
        rule.put("response_remove_headers", strings(input.get("response_remove_headers")));
        rule.put("response_body_replace", pairs(input.get("response_body_replace")));
        rule.put("block", bool(input.get("block")));
        return rule;
    }

    private static List<String[]> replacements(Object value) {
        List<String[]> out = new ArrayList<>();
        for (Map<String, Object> pair : pairs(value)) {
            out.add(new String[] { str(pair.get("regex")), str(pair.get("with")) });
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> pairs(Object value) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (!(value instanceof List<?> list)) return out;
        for (Object item : list) {
            if (item instanceof Map<?, ?> source) {
                Map<String, Object> pair = new LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : source.entrySet()) pair.put(String.valueOf(entry.getKey()), entry.getValue());
                if (!str(pair.get("regex")).isEmpty()) out.add(pair);
            }
        }
        return out;
    }

    private static Map<String, Object> map(Object value) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (!(value instanceof Map<?, ?> source)) return out;
        for (Map.Entry<?, ?> entry : source.entrySet()) out.put(String.valueOf(entry.getKey()), entry.getValue());
        return out;
    }

    private static List<String> strings(Object value) {
        List<String> out = new ArrayList<>();
        if (!(value instanceof List<?> list)) {
            String single = str(value);
            if (!single.isEmpty()) out.add(single);
            return out;
        }
        for (Object item : list) {
            String text = str(item).trim();
            if (!text.isEmpty()) out.add(text);
        }
        return out;
    }

    private static Pattern compile(String regex) {
        try {
            return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException error) {
            throw new Routes.BadRequest("invalid url_regex: " + error.getDescription());
        }
    }

    private static boolean bool(Object value) {
        if (value instanceof Boolean flag) return flag;
        if (value instanceof Number number) return number.intValue() != 0;
        String text = str(value).toLowerCase(Locale.ROOT);
        return text.equals("true") || text.equals("1") || text.equals("yes");
    }

    private static String str(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    /** Rewrites Burp's own traffic (Proxy, Repeater, Scanner, Intruder). */
    private final class Rewriter implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
            HttpRequest rewritten = apply(request);
            return RequestToBeSentAction.continueWith(rewritten == null ? request : rewritten);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
            return ResponseReceivedAction.continueWith(applyResponse(response.initiatingRequest(), response));
        }
    }
}