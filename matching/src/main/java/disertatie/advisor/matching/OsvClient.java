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

        Set<String> presentGroupArtifacts = new HashSet<>();
        for (Component c : components) {
            presentGroupArtifacts.add(c.group() + ":" + c.artifact());
        }

        List<Vulnerability> out = new ArrayList<>();
        for (String osvId : osvIds) {
            try {
                out.addAll(fetchVuln(osvId, presentGroupArtifacts));
            } catch (Exception e) {

            }
        }
        return out;
    }

    private List<Vulnerability> fetchVuln(String osvId, Set<String> presentGroupArtifacts) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(VULN_URL + osvId))
                .timeout(Duration.ofSeconds(15))
                .GET()
                .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) return List.of();

        return parseVulnerabilities(mapper.readTree(resp.body()), presentGroupArtifacts);
    }

    List<Vulnerability> parseVulnerabilities(JsonNode root, Set<String> presentGroupArtifacts) {
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

        Vulnerability fallback = null;
        for (JsonNode aff : root.path("affected")) {
            JsonNode pkg = aff.path("package");
            String purl = resolveAffectedPurl(pkg);
            if (purl == null) continue;

            String[] rangeAndFixed = extractRangeAndFixedVersion(aff);
            Vulnerability candidate = new Vulnerability(cveId, purl, rangeAndFixed[0], rangeAndFixed[1], cvssScore, cvssVector);

            if (fallback == null) fallback = candidate;

            String groupArtifact = groupArtifactFromPurl(purl);
            if (groupArtifact != null && presentGroupArtifacts.contains(groupArtifact)) {
                return List.of(candidate);
            }
        }

        return fallback != null ? List.of(fallback) : List.of();
    }

    private String[] extractRangeAndFixedVersion(JsonNode aff) {
        String affectedRange = null;
        String fixedVersion = null;
        JsonNode ranges = aff.path("ranges");
        if (ranges.isArray() && !ranges.isEmpty()) {
            JsonNode range = ranges.get(0);
            StringBuilder sb = new StringBuilder();
            for (JsonNode ev : range.path("events")) {
                if (ev.has("introduced")) sb.append(">=").append(ev.get("introduced").asText()).append(" ");
                if (ev.has("fixed")) {
                    String fixed = ev.get("fixed").asText();
                    sb.append("<").append(fixed).append(" ");
                    if (fixedVersion == null) fixedVersion = fixed;
                }
            }
            affectedRange = sb.toString().trim();
        }
        return new String[]{ affectedRange, fixedVersion };
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
