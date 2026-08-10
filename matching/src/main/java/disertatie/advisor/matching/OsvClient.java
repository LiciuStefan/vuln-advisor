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

        // Pas 3: GET detalii pentru fiecare vuln OSV, extrage CVE
        List<Vulnerability> out = new ArrayList<>();
        for (String osvId : osvIds) {
            try {
                Vulnerability v = fetchVuln(osvId);
                if (v != null) out.add(v);
            } catch (Exception e) {

            }
        }
        return out;
    }

    private Vulnerability fetchVuln(String osvId) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(VULN_URL + osvId))
                .timeout(Duration.ofSeconds(15))
                .GET()
                .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) return null;

        JsonNode root = mapper.readTree(resp.body());

        // CVE din câmpul aliases
        String cveId = null;
        for (JsonNode alias : root.path("aliases")) {
            String a = alias.asText();
            if (a.startsWith("CVE-")) { cveId = a; break; }
        }
        if (cveId == null) cveId = osvId;

        // Vector CVSS şi scor
        String cvssVector = null;
        double cvssScore = 0.0;
        for (JsonNode sev : root.path("severity")) {
            if ("CVSS_V3".equals(sev.path("type").asText())) {
                cvssVector = sev.path("score").asText(null);
                if (cvssVector != null) cvssScore = CvssCalculator.calculate(cvssVector);
                break;
            }
        }

        // Purl afectat şi interval de versiuni
        String affectedPurl = null;
        String affectedRange = null;
        String fixedVersion = null;

        for (JsonNode aff : root.path("affected")) {
            JsonNode pkg = aff.path("package");
            String purl = resolveAffectedPurl(pkg);
            if (purl == null) continue;

            affectedPurl = purl;
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
            break;
        }

        if (affectedPurl == null) return null;

        return new Vulnerability(cveId, affectedPurl, affectedRange, fixedVersion, cvssScore, cvssVector);
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
}
