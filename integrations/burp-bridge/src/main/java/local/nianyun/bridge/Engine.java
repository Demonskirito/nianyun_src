package local.nianyun.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/**
 * Intruder-equivalent attack engine.
 *
 * Burp's Montoya API can open an Intruder tab and register payload generators, but it cannot launch
 * an attack. This class drives the same work through Burp's own HTTP stack: it substitutes payloads
 * into {@code §marker§} positions of a raw request template and sends the combinations with
 * bounded concurrency, delay, stop conditions and match filters.
 */
final class Engine {

    /** Hard ceiling so a mistaken cluster-bomb cannot queue a million requests. */
    static final int MAX_TOTAL = 5000;
    private static final int MAX_HITS = 500;
    private static final int MAX_PREVIEW = 2048;

    private final MontoyaApi api;
    private final Map<String, Attack> attacks = new ConcurrentHashMap<>();
    private final ExecutorService executor = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "nianyun-intruder");
        thread.setDaemon(true);
        return thread;
    });

    Engine(MontoyaApi api) {
        this.api = api;
    }

    static final class Attack {
        final String id = "atk-" + UUID.randomUUID().toString().substring(0, 8);
        final long startedAt = System.currentTimeMillis();
        String type = "sniper";
        String url = "";
        int markers;
        int planned;
        volatile int sent;
        volatile int matched;
        volatile int errors;
        volatile int blocked;
        volatile boolean stop;
        volatile boolean done;
        volatile String error;
        boolean race;
        int threads;
        String extractNames = "";
        volatile long finishedAt;
        final List<Map<String, Object>> hits = Collections.synchronizedList(new ArrayList<>());
        final List<Map<String, Object>> samples = Collections.synchronizedList(new ArrayList<>());

        Map<String, Object> snapshot() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("audit_id", id);
            out.put("attack_id", id);
            out.put("type", type);
            out.put("url", url);
            out.put("markers", markers);
            out.put("race", race);
            if (race) out.put("threads", threads);
            if (!extractNames.isEmpty()) out.put("extract", extractNames);
            out.put("planned", planned);
            out.put("sent", sent);
            out.put("matched", matched);
            out.put("errors", errors);
            out.put("blocked", blocked);
            out.put("stop_requested", stop);
            out.put("done", done);
            if (error != null) out.put("error", error);
            out.put("elapsed_ms", (finishedAt > 0 ? finishedAt : System.currentTimeMillis()) - startedAt);
            out.put("hits", new ArrayList<>(hits));
            out.put("samples", new ArrayList<>(samples));
            return out;
        }
    }

    String start(Map<String, Object> input, String defaultHost, boolean defaultSecure) {
        String template = str(input.get("template"));
        String type = lower(str(input.get("type")));
        if (type.isEmpty()) type = "sniper";
        if (!List.of("sniper", "battering_ram", "pitchfork", "cluster_bomb").contains(type)) {
            throw new Routes.BadRequest("type must be sniper, battering_ram, pitchfork or cluster_bomb");
        }
        if (template.isBlank()) throw new Routes.BadRequest("template is required (raw request with §markers§)");
        if (!template.contains("§")) throw new Routes.BadRequest("template must contain at least one §marker§ position");

        String url = str(input.get("url"));
        String host = str(input.get("host"));
        if (host.isEmpty()) host = defaultHost;
        int port = intOf(input.get("port"), defaultSecure ? 443 : 80);
        boolean secure = boolOf(input.get("secure"), defaultSecure);

        List<List<String>> lists = payloadLists(input);
        int markers = countMarkers(template);

        Attack attack = new Attack();
        attack.type = type;
        attack.url = url;
        attack.markers = markers;

        List<String[]> combinations = combinations(type, markers, lists);
        int maxRequests = Math.min(MAX_TOTAL, Math.max(1, intOf(input.get("max_requests"), 200)));
        if (combinations.size() > maxRequests) combinations = combinations.subList(0, maxRequests);
        attack.planned = combinations.size();

        if (boolOf(input.get("dry_run"), false)) {
            attack.done = true;
            attack.finishedAt = System.currentTimeMillis();
            attacks.put(attack.id, attack);
            return attack.id;
        }

        String templateBody = template;
        String serviceHost = host;
        int servicePort = port;
        boolean serviceSecure = secure;
        boolean follow = boolOf(input.get("follow_redirects"), false);
        int concurrency = Math.max(1, Math.min(20, intOf(input.get("concurrency"), 4)));
        int delayMs = Math.max(0, Math.min(10_000, intOf(input.get("delay_ms"), 0)));
        long stopAfterMs = Math.max(0, Math.min(600_000, intOf(input.get("stop_after_ms"), 0)));
        boolean stopOnMatch = boolOf(input.get("stop_on_match"), false);
        List<Integer> matchStatus = ints(input.get("match_status"));
        int minLength = intOf(input.get("match_length_min"), -1);
        int maxLength = intOf(input.get("match_length_max"), -1);
        String regex = str(input.get("match_regex"));
        Pattern pattern = regex.isEmpty() ? null : Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        boolean keepAll = matchStatus.isEmpty() && minLength < 0 && maxLength < 0 && pattern == null;
        boolean race = boolOf(input.get("race"), false);
        int threads = Math.max(0, Math.min(50, intOf(input.get("threads"), 0)));
        List<Extract> extracts = extracts(input.get("extract"));
        attack.race = race;
        attack.threads = threads;
        StringBuilder names = new StringBuilder();
        for (Extract extract : extracts) names.append(names.length() == 0 ? "" : ",").append(extract.name);
        attack.extractNames = names.toString();

        attacks.put(attack.id, attack);
        List<String[]> plan = combinations;
        executor.submit(() -> run(attack, templateBody, plan, serviceHost, servicePort, serviceSecure, follow,
                concurrency, delayMs, stopAfterMs, stopOnMatch, matchStatus, minLength, maxLength, pattern, keepAll,
                race, threads, extracts));
        return attack.id;
    }

    private void run(Attack attack, String template, List<String[]> plan, String host, int port, boolean secure,
                     boolean follow, int concurrency, int delayMs, long stopAfterMs, boolean stopOnMatch,
                     List<Integer> matchStatus, int minLength, int maxLength, Pattern pattern, boolean keepAll,
                     boolean race, int threads, List<Extract> extracts) {
        HttpService service = HttpService.httpService(host, port, secure);
        RequestOptions options = RequestOptions.requestOptions()
                .withRedirectionMode(follow ? RedirectionMode.ALWAYS : RedirectionMode.NEVER);
        try {
            if (race) {
                runRace(attack, template, plan, service, options, matchStatus, minLength, maxLength, pattern, keepAll,
                        stopOnMatch, threads, extracts);
            } else {
                runBatched(attack, template, plan, service, options, concurrency, delayMs, stopAfterMs, stopOnMatch,
                        matchStatus, minLength, maxLength, pattern, keepAll, extracts);
            }
        } catch (RuntimeException error) {
            attack.error = error.getMessage();
        } finally {
            attack.done = true;
            attack.finishedAt = System.currentTimeMillis();
        }
    }

    private void runBatched(Attack attack, String template, List<String[]> plan, HttpService service,
                            RequestOptions options, int concurrency, int delayMs, long stopAfterMs, boolean stopOnMatch,
                            List<Integer> matchStatus, int minLength, int maxLength, Pattern pattern, boolean keepAll,
                            List<Extract> extracts) {
        int index = 0;
        for (int start = 0; start < plan.size(); start += concurrency) {
            if (attack.stop) break;
            if (stopAfterMs > 0 && System.currentTimeMillis() - attack.startedAt > stopAfterMs) break;
            List<java.util.concurrent.Future<?>> batch = new ArrayList<>();
            for (int offset = start; offset < Math.min(plan.size(), start + concurrency); offset++) {
                final int position = index++;
                batch.add(executor.submit(() -> fire(attack, template, plan.get(position), position, service, options,
                        matchStatus, minLength, maxLength, pattern, keepAll, stopOnMatch, extracts)));
            }
            for (java.util.concurrent.Future<?> future : batch) {
                try {
                    future.get();
                } catch (Exception ignored) {
                    // A single failed request must not abort the attack.
                }
            }
            if (delayMs > 0 && start + concurrency < plan.size()) {
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    /**
     * Race mode: every worker waits on one gate, then all requests leave together.
     *
     * This is a concurrent burst, not a last-byte-sync single-packet attack: Montoya's
     * {@code http.sendRequest} owns the socket, so the bridge cannot hold the final byte back the way
     * Turbo Intruder does. It still packs the requests into the same instant far better than the
     * batched loop, which is what most duplicate-claim and coupon tests need.
     */
    private void runRace(Attack attack, String template, List<String[]> plan, HttpService service,
                         RequestOptions options, List<Integer> matchStatus, int minLength, int maxLength,
                         Pattern pattern, boolean keepAll, boolean stopOnMatch, int threads, List<Extract> extracts) {
        int workers = Math.min(plan.size(), Math.max(2, threads > 0 ? threads : Math.min(16, plan.size())));
        attack.threads = workers;
        java.util.concurrent.CountDownLatch ready = new java.util.concurrent.CountDownLatch(workers);
        java.util.concurrent.CountDownLatch gate = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicInteger cursor = new java.util.concurrent.atomic.AtomicInteger();
        List<java.util.concurrent.Future<?>> pool = new ArrayList<>();
        for (int worker = 0; worker < workers; worker++) {
            pool.add(executor.submit(() -> {
                ready.countDown();
                try {
                    gate.await(10, java.util.concurrent.TimeUnit.SECONDS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                }
                int position;
                while ((position = cursor.getAndIncrement()) < plan.size()) {
                    if (attack.stop) return;
                    fire(attack, template, plan.get(position), position, service, options, matchStatus, minLength,
                            maxLength, pattern, keepAll, stopOnMatch, extracts);
                }
            }));
        }
        try {
            ready.await(10, java.util.concurrent.TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        gate.countDown();
        for (java.util.concurrent.Future<?> future : pool) {
            try {
                future.get();
            } catch (Exception ignored) {
                // Keep the rest of the burst going.
            }
        }
    }

    /** One request: render, send, record. Shared by the batched loop and race mode. */
    private void fire(Attack attack, String template, String[] payloads, int position, HttpService service,
                      RequestOptions options, List<Integer> matchStatus, int minLength, int maxLength,
                      Pattern pattern, boolean keepAll, boolean stopOnMatch, List<Extract> extracts) {
        if (attack.stop) return;
        long began = System.currentTimeMillis();
        try {
            String raw = render(template, payloads);
            HttpRequest request = HttpRequest.httpRequest(service, normalize(raw));
            HttpRequest prepared = Rules.engine(api).apply(request);
            if (prepared == null) {
                // A rewrite rule with block=true stops this payload before it leaves Burp.
                attack.blocked++;
                return;
            }
            HttpRequestResponse rr = api.http().sendRequest(prepared, options);
            attack.sent++;
            if (rr == null || !rr.hasResponse()) return;
            HttpResponse response = Rules.engine(api).applyResponse(prepared, rr.response());
            int status = response.statusCode();
            int length = response.body().length();
            boolean hit = matches(status, length, response, matchStatus, minLength, maxLength, pattern);
            if (hit && attack.hits.size() < MAX_HITS) {
                Map<String, Object> row = row(position, payloads, status, length,
                        System.currentTimeMillis() - began, preview(response));
                Map<String, String> extracted = extractAll(response, extracts);
                if (!extracted.isEmpty()) row.put("extracted", extracted);
                attack.hits.add(row);
                attack.matched++;
                if (stopOnMatch) attack.stop = true;
            } else if (keepAll && attack.samples.size() < 20) {
                attack.samples.add(row(position, payloads, status, length, System.currentTimeMillis() - began, ""));
            }
        } catch (RuntimeException error) {
            attack.errors++;
        }
    }

    private static Map<String, String> extractAll(HttpResponse response, List<Extract> extracts) {
        Map<String, String> out = new LinkedHashMap<>();
        if (extracts.isEmpty()) return out;
        String body = response.bodyToString();
        if (body == null) return out;
        for (Extract extract : extracts) {
            java.util.regex.Matcher matcher = extract.pattern.matcher(body);
            if (!matcher.find()) continue;
            try {
                String value = matcher.group(extract.group);
                if (value != null) out.put(extract.name, value.length() > 512 ? value.substring(0, 512) : value);
            } catch (IndexOutOfBoundsException ignored) {
                // A bad group number is a rule bug, not an attack failure.
            }
        }
        return out;
    }

    private static List<Extract> extracts(Object value) {
        List<Extract> out = new ArrayList<>();
        if (!(value instanceof List<?> list)) return out;
        int fallback = 0;
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> source)) continue;
            String regex = str(source.get("regex"));
            if (regex.isEmpty()) continue;
            String name = str(source.get("name"));
            if (name.isEmpty()) name = "extract" + (++fallback);
            int group = 1;
            Object rawGroup = source.get("group");
            if (rawGroup instanceof Number number) group = number.intValue();
            else if (!str(rawGroup).isEmpty()) group = intOf(rawGroup, 1);
            try {
                out.add(new Extract(name, Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.DOTALL), group));
            } catch (java.util.regex.PatternSyntaxException error) {
                throw new Routes.BadRequest("invalid extract regex for " + name + ": " + error.getDescription());
            }
        }
        return out;
    }

    private static final class Extract {
        private final String name;
        private final Pattern pattern;
        private final int group;

        private Extract(String name, Pattern pattern, int group) {
            this.name = name;
            this.pattern = pattern;
            this.group = group;
        }
    }

    private static boolean matches(int status, int length, HttpResponse response, List<Integer> statuses,
                                   int minLength, int maxLength, Pattern pattern) {
        if (!statuses.isEmpty() && !statuses.contains(status)) return false;
        if (minLength >= 0 && length < minLength) return false;
        if (maxLength >= 0 && length > maxLength) return false;
        if (pattern != null) {
            String body = response.bodyToString();
            if (body == null || !pattern.matcher(body).find()) return false;
        }
        return true;
    }

    private static Map<String, Object> row(int index, String[] payloads, int status, int length, long elapsed, String preview) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("index", index);
        row.put("payload", String.join(" | ", payloads));
        row.put("status", status);
        row.put("length", length);
        row.put("elapsed_ms", elapsed);
        if (!preview.isEmpty()) row.put("preview", preview);
        return row;
    }

    private static String preview(HttpResponse response) {
        String body = response.bodyToString();
        if (body == null) return "";
        return body.length() > MAX_PREVIEW ? body.substring(0, MAX_PREVIEW) : body;
    }

    String status(String id) {
        Attack attack = id == null || id.isEmpty() ? latest() : attacks.get(id);
        if (attack == null) throw new Routes.BadRequest("unknown attack id");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.putAll(attack.snapshot());
        return Json.write(out);
    }

    String stop(String id) {
        Attack attack = id == null || id.isEmpty() ? latest() : attacks.get(id);
        if (attack == null) throw new Routes.BadRequest("unknown attack id");
        attack.stop = true;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("attack_id", attack.id);
        out.put("stop_requested", true);
        return Json.write(out);
    }

    String list() {
        List<Object> rows = new ArrayList<>();
        for (Attack attack : attacks.values()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("attack_id", attack.id);
            row.put("type", attack.type);
            row.put("url", attack.url);
            row.put("planned", attack.planned);
            row.put("sent", attack.sent);
            row.put("matched", attack.matched);
            row.put("done", attack.done);
            row.put("elapsed_ms", (attack.finishedAt > 0 ? attack.finishedAt : System.currentTimeMillis()) - attack.startedAt);
            rows.add(row);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("total", rows.size());
        out.put("attacks", rows);
        return Json.write(out);
    }

    private Attack latest() {
        Attack newest = null;
        for (Attack attack : attacks.values()) {
            if (newest == null || attack.startedAt > newest.startedAt) newest = attack;
        }
        if (newest == null) throw new Routes.BadRequest("no attack has been started yet");
        return newest;
    }

    private static int countMarkers(String template) {
        int count = 0;
        for (int i = 0; i < template.length(); i++) if (template.charAt(i) == '§') count++;
        return Math.max(1, count / 2);
    }

    /**
     * Renders one request from the template.
     *
     * Text between two § characters is a label and is replaced wholesale, so both Burp's plain
     * `§§` positions and the agent's `§name§` positions mean "put the payload here".
     */
    private static String render(String template, String[] payloads) {
        String[] parts = template.split("§", -1);
        StringBuilder out = new StringBuilder(template.length() + 64);
        for (int i = 0; i < parts.length; i++) {
            if (i % 2 == 1) {
                int slot = i / 2;
                if (slot < payloads.length) out.append(payloads[slot]);
            } else {
                out.append(parts[i]);
            }
        }
        return out.toString();
    }

    /**
     * Rebuilds the template with CRLF line endings.
     *
     * Burp parses the raw message itself, so a request line that already ends in CR must not gain a
     * second CR; a malformed leading line makes nginx answer 400 and would look like a payload
     * result instead of a bridge bug.
     */
    private static String normalize(String raw) {
        String text = raw.replace("\r\n", "\n").replace('\r', '\n');
        int headerEnd = text.indexOf("\n\n");
        String head = headerEnd < 0 ? text : text.substring(0, headerEnd);
        String body = headerEnd < 0 ? "" : text.substring(headerEnd + 2);
        String[] lines = head.split("\n", -1);
        StringBuilder out = new StringBuilder(text.length() + 32);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].endsWith("\r") ? lines[i].substring(0, lines[i].length() - 1) : lines[i];
            if (i == 0 && !line.isBlank() && !line.contains(" HTTP/")) {
                line = line.trim() + " HTTP/1.1";
            }
            out.append(line).append("\r\n");
        }
        out.append("\r\n");
        if (!body.isEmpty()) out.append(body);
        return out.toString();
    }

    private static int intOf(Object value, int fallback) {
        if (value instanceof Number number) return number.intValue();
        try {
            return value == null ? fallback : Integer.parseInt(String.valueOf(value).trim());
        } catch (RuntimeException ignored) {
            return fallback;
        }
    }

    private static boolean boolOf(Object value, boolean fallback) {
        if (value instanceof Boolean flag) return flag;
        String text = value == null ? "" : String.valueOf(value).trim();
        if (text.isEmpty()) return fallback;
        return text.equalsIgnoreCase("true") || text.equals("1");
    }

    private static String str(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static String lower(String value) {
        return value == null ? "" : value.trim().toLowerCase(java.util.Locale.ROOT);
    }

    private static List<Integer> ints(Object value) {
        List<Integer> out = new ArrayList<>();
        if (value instanceof List<?> list) {
            for (Object item : list) out.add(intOf(item, 0));
        } else if (value != null && !String.valueOf(value).isBlank()) {
            for (String part : String.valueOf(value).split(",")) {
                try {
                    out.add(Integer.parseInt(part.trim()));
                } catch (RuntimeException ignored) {
                    // Skip a malformed entry instead of failing the whole attack.
                }
            }
        }
        return out;
    }

    private static List<List<String>> payloadLists(Map<String, Object> input) {
        List<List<String>> lists = new ArrayList<>();
        Object multiple = input.get("payload_lists");
        if (multiple instanceof List<?> outer) {
            for (Object item : outer) {
                List<String> one = new ArrayList<>();
                if (item instanceof List<?> inner) for (Object payload : inner) one.add(str(payload));
                else one.add(str(item));
                lists.add(one);
            }
        }
        List<String> single = new ArrayList<>();
        Object payloads = input.get("payloads");
        if (payloads instanceof List<?> list) for (Object item : list) single.add(str(item));
        if (single.isEmpty()) {
            String words = str(input.get("words"));
            if (!words.isBlank()) {
                for (String line : words.replace("\r\n", "\n").split("\n")) {
                    if (!line.isBlank()) single.add(line);
                }
            }
        }
        Object range = input.get("range");
        if (single.isEmpty() && range instanceof Map<?, ?> spec) {
            int from = intOf(spec.get("from"), 1);
            int to = intOf(spec.get("to"), from + 99);
            int step = Math.max(1, intOf(spec.get("step"), 1));
            int pad = Math.max(0, Math.min(10, intOf(spec.get("pad"), 0)));
            for (int value = from; value <= to && single.size() < MAX_TOTAL; value += step) {
                single.add(pad > 0 ? String.format("%0" + pad + "d", value) : String.valueOf(value));
            }
        }
        if (lists.isEmpty()) lists.add(single);
        if (lists.get(0).isEmpty()) throw new Routes.BadRequest("no payloads: provide payloads, payload_lists, words or range");
        return lists;
    }

    private static List<String[]> combinations(String type, int markers, List<List<String>> lists) {
        List<String[]> out = new ArrayList<>();
        List<String> primary = lists.get(0);
        switch (type) {
            case "battering_ram" -> {
                for (String payload : primary) {
                    String[] row = new String[markers];
                    java.util.Arrays.fill(row, payload);
                    out.add(row);
                }
            }
            case "pitchfork" -> {
                int rows = primary.size();
                for (List<String> list : lists) rows = Math.min(rows, list.size());
                for (int i = 0; i < rows; i++) {
                    String[] row = new String[markers];
                    for (int m = 0; m < markers; m++) {
                        List<String> list = lists.get(Math.min(m, lists.size() - 1));
                        row[m] = list.get(Math.min(i, list.size() - 1));
                    }
                    out.add(row);
                }
            }
            case "cluster_bomb" -> {
                List<String[]> product = new ArrayList<>();
                product.add(new String[markers]);
                for (int m = 0; m < markers; m++) {
                    List<String> list = lists.get(Math.min(m, lists.size() - 1));
                    List<String[]> next = new ArrayList<>();
                    for (String[] partial : product) {
                        for (String payload : list) {
                            String[] copy = partial.clone();
                            copy[m] = payload;
                            next.add(copy);
                            if (next.size() >= MAX_TOTAL) break;
                        }
                        if (next.size() >= MAX_TOTAL) break;
                    }
                    product = next;
                }
                out.addAll(product);
            }
            default -> {
                // sniper: one marker varies at a time, the others stay literal.
                for (int m = 0; m < markers; m++) {
                    for (String payload : primary) {
                        String[] row = new String[markers];
                        for (int other = 0; other < markers; other++) row[other] = other == m ? payload : "";
                        out.add(row);
                    }
                }
            }
        }
        if (out.size() > MAX_TOTAL) return new ArrayList<>(out.subList(0, MAX_TOTAL));
        return out;
    }
}