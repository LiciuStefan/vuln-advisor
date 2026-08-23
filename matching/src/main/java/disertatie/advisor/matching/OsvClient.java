package disertatie.advisor.matching;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import disertatie.contracts.model.Component;
import disertatie.contracts.model.Vulnerability;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;

public class OsvClient {

    private static final String QUERYBATCH = "https://api.osv.dev/v1/querybatch";
    private static final String VULN_URL   = "https://api.osv.dev/v1/vulns/";

    private static final Map<String, Double> QUALITATIVE_SEVERITY_UPPER_BOUND = Map.of(
            "LOW", 3.9, "MODERATE", 6.9, "MEDIUM", 6.9, "HIGH", 8.9, "CRITICAL", 10.0
    );

    private final HttpClient http;
    private final ObjectMapper mapper;

    public OsvClient(ObjectMapper mapper) {
        this.mapper = mapper;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .build();
    }

    public List<Vulnerability> query(List<Component> components) throws Exception {
        if (components.isEmpty()) return List.of();

        // Pas 1: querybatch → obţine ID-urile OSV per purl
        ArrayNode queries = mapper.createArrayNode();
        for (Component component : components) {
            ObjectNode q = mapper.createObjectNode();
            q.put("package", mapper.createObjectNode().put("purl", component.purl()));
            queries.add(q);
        }

        ObjectNode body = mapper.createObjectNode();
        body.set("queries", queries);
        String requestBody = mapper.writeValueAsString(body);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(QUERYBATCH))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new RuntimeException("OSV querybatch a returnat HTTP " + resp.statusCode());
        }

        // Pas 2: colectăm ID-urile unice OSV
        JsonNode results = mapper.readTree(resp.body()).path("results");
        Set<String> osvIds = new LinkedHashSet<>();
        for (int i = 0; i < results.size(); i++) {
            JsonNode vulns = results.get(i).path("vulns");
            for (JsonNode v : vulns) {
                String id = v.path("id").asText();
                if (!id.isBlank()) osvIds.add(id);
            }
        }

        Map<String, String> currentVersionByGroupArtifact = new HashMap<>();
        for (Component c : components) {
            if (c.version() == null || c.version().isBlank()) continue;
            String groupArtifact = c.group() + ":" + c.artifact();
            String existing = currentVersionByGroupArtifact.get(groupArtifact);
            if (existing == null || compareVersions(c.version(), existing) > 0) {
                currentVersionByGroupArtifact.put(groupArtifact, c.version());
            }
        }

        List<Vulnerability> out = new ArrayList<>();
        for (String osvId : osvIds) {
            try {
                out.addAll(fetchVuln(osvId, currentVersionByGroupArtifact));
            } catch (Exception e) {

            }
        }
        return out;
    }

    private List<Vulnerability> fetchVuln(String osvId, Map<String, String> currentVersionByGroupArtifact) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(VULN_URL + osvId))
                .timeout(Duration.ofSeconds(15))
                .GET()
                .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) return List.of();

        return parseVulnerabilities(mapper.readTree(resp.body()), currentVersionByGroupArtifact);
    }

    List<Vulnerability> parseVulnerabilities(JsonNode root, Map<String, String> currentVersionByGroupArtifact) {
        String osvId = root.path("id").asText();
        String cveId = null;
        for (JsonNode alias : root.path("aliases")) {
            String a = alias.asText();
            if (a.startsWith("CVE-")) { cveId = a; break; }
        }
        if (cveId == null) cveId = osvId;

        String cvssVector = null;
        double cvssScore = 0.0;
        for (JsonNode sev : root.path("severity")) {
            if ("CVSS_V3".equals(sev.path("type").asText())) {
                cvssVector = sev.path("score").asText(null);
                if (cvssVector != null) cvssScore = CvssCalculator.calculate(cvssVector);
                break;
            }
        }
        if (cvssVector == null) {
            // Fallback CVSS v4.0: fără formula exactă
            for (JsonNode sev : root.path("severity")) {
                if ("CVSS_V4".equals(sev.path("type").asText())) {
                    cvssVector = sev.path("score").asText(null);
                    break;
                }
            }
            if (cvssVector != null) {
                String qualitative = root.path("database_specific").path("severity").asText("").toUpperCase();
                cvssScore = QUALITATIVE_SEVERITY_UPPER_BOUND.getOrDefault(qualitative, 0.0);
            }
        }

        // Acelaşi advisory poate descrie mai multe branch-uri de release, fie ca blocuri
        // `affected` separate pentru acelaşi pachet, fie ca intervale multiple în acelaşi
        // bloc. Preferăm blocul al cărui interval CONŢINE versiunea curentă a componentei;
        // dacă niciunul nu o conţine, reţinem primul bloc cu GroupArtifact prezent, apoi primul bloc oarecare.
        Vulnerability fallback = null;
        Vulnerability groupArtifactMatch = null;
        for (JsonNode aff : root.path("affected")) {
            JsonNode pkg = aff.path("package");
            String purl = resolveAffectedPurl(pkg);
            if (purl == null) continue;

            String groupArtifact = groupArtifactFromPurl(purl);
            boolean present = groupArtifact != null && currentVersionByGroupArtifact.containsKey(groupArtifact);
            String currentVersion = present ? currentVersionByGroupArtifact.get(groupArtifact) : null;

            RangeSelection selection = selectRange(aff, currentVersion);
            Vulnerability candidate = new Vulnerability(cveId, purl, selection.affectedRange(),
                    selection.fixedVersion(), cvssScore, cvssVector);

            if (present && selection.containsCurrent()) {
                return List.of(candidate);
            }
            if (present && groupArtifactMatch == null) groupArtifactMatch = candidate;
            if (fallback == null) fallback = candidate;
        }

        if (groupArtifactMatch != null) return List.of(groupArtifactMatch);
        return fallback != null ? List.of(fallback) : List.of();
    }

    /* Un segment afectat [introduced, fixed) — `fixed` null înseamnă branch încă nefixat. */
    private record Segment(String introduced, String fixed) {}

    private record RangeSelection(String affectedRange, String fixedVersion, boolean containsCurrent) {}

    private RangeSelection selectRange(JsonNode aff, String currentVersion) {
        List<Segment> segments = new ArrayList<>();
        for (JsonNode range : aff.path("ranges")) {
            if ("GIT".equalsIgnoreCase(range.path("type").asText(""))) continue;
            String introduced = null;
            for (JsonNode ev : range.path("events")) {
                if (ev.has("introduced")) {
                    if (introduced != null) segments.add(new Segment(introduced, null));
                    introduced = ev.get("introduced").asText();
                }
                if (ev.has("fixed")) {
                    segments.add(new Segment(introduced, ev.get("fixed").asText()));
                    introduced = null;
                }
            }
            if (introduced != null) segments.add(new Segment(introduced, null));
        }
        if (segments.isEmpty()) return new RangeSelection(null, null, false);

        StringBuilder sb = new StringBuilder();
        for (Segment s : segments) {
            if (s.introduced() != null) sb.append(">=").append(s.introduced()).append(" ");
            if (s.fixed() != null) sb.append("<").append(s.fixed()).append(" ");
        }

        Segment selected = null;
        if (currentVersion != null && !currentVersion.isBlank()) {
            for (Segment s : segments) {
                if (segmentContains(s, currentVersion)) { selected = s; break; }
            }
        }

        String fixedVersion;
        if (selected != null) {
            // fixed null aici = versiunea curentă e pe un branch încă nefixat
            fixedVersion = selected.fixed();
        } else {
            fixedVersion = segments.stream().map(Segment::fixed).filter(Objects::nonNull).findFirst().orElse(null);
        }
        if (fixedVersion != null && currentVersion != null && !currentVersion.isBlank()
                && compareVersions(fixedVersion, currentVersion) < 0) {
            fixedVersion = null;
        }
        return new RangeSelection(sb.toString().trim(), fixedVersion, selected != null);
    }

    private boolean segmentContains(Segment s, String version) {
        boolean aboveIntroduced = s.introduced() == null || compareVersions(version, s.introduced()) >= 0;
        boolean belowFixed = s.fixed() == null || compareVersions(version, s.fixed()) < 0;
        return aboveIntroduced && belowFixed;
    }

    static int compareVersions(String a, String b) {
        int[] ta = numericTuple(a);
        int[] tb = numericTuple(b);
        int len = Math.max(ta.length, tb.length);
        for (int i = 0; i < len; i++) {
            int va = i < ta.length ? ta[i] : 0;
            int vb = i < tb.length ? tb[i] : 0;
            if (va != vb) return Integer.compare(va, vb);
        }
        return 0;
    }

    private static int[] numericTuple(String version) {
        String[] parts = version.split("[.\\-]");
        int count = 0;
        int[] nums = new int[parts.length];
        for (String part : parts) {
            try {
                nums[count] = Integer.parseInt(part);
                count++;
            } catch (NumberFormatException e) {
                break;
            }
        }
        return Arrays.copyOf(nums, count);
    }

    String resolveAffectedPurl(JsonNode pkg) {
        String purl = pkg.path("purl").asText(null);
        if (purl != null) return purl;

        if (!"Maven".equalsIgnoreCase(pkg.path("ecosystem").asText(""))) return null;
        String name = pkg.path("name").asText(null);
        if (name == null) return null;
        int colon = name.indexOf(':');
        if (colon <= 0 || colon == name.length() - 1) return null;
        return "pkg:maven/" + name.substring(0, colon) + "/" + name.substring(colon + 1);
    }

    /* Extrage "groupId:artifactId" dintr-un purl "pkg:maven/<group>/<artifact>[@<version>]". */
    private String groupArtifactFromPurl(String purl) {
        if (purl == null || !purl.startsWith("pkg:maven/")) return null;
        String rest = purl.substring("pkg:maven/".length());
        int at = rest.indexOf('@');
        if (at >= 0) rest = rest.substring(0, at);
        int slash = rest.indexOf('/');
        if (slash <= 0 || slash == rest.length() - 1) return null;
        return rest.substring(0, slash) + ":" + rest.substring(slash + 1);
    }
}
