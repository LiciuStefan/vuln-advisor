package disertatie.advisor.matching;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class KevCatalog {

    private static final String KEV_URL =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private static final Duration TTL = Duration.ofHours(24);

    private final HttpClient http;
    private final ObjectMapper mapper;

    private volatile Map<String, String> catalog = null;
    private volatile Instant loadedAt = Instant.EPOCH;

    public KevCatalog(ObjectMapper mapper) {
        this.mapper = mapper;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .build();
    }

    public boolean isKnownExploited(String cveId) {
        return getCatalog().containsKey(cveId);
    }

    public String dateAdded(String cveId) {
        return getCatalog().get(cveId);
    }

    private Map<String, String> getCatalog() {
        if (catalog == null || Instant.now().isAfter(loadedAt.plus(TTL))) {
            synchronized (this) {
                if (catalog == null || Instant.now().isAfter(loadedAt.plus(TTL))) {
                    catalog = loadCatalog();
                    loadedAt = Instant.now();
                }
            }
        }
        return catalog;
    }

    private Map<String, String> loadCatalog() {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(KEV_URL))
                    .timeout(Duration.ofSeconds(30))
                    .GET()
                    .build();

            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) return Map.of();

            JsonNode root = mapper.readTree(resp.body());
            Map<String, String> result = new HashMap<>();
            for (JsonNode entry : root.path("vulnerabilities")) {
                String cveId = entry.path("cveID").asText(null);
                if (cveId != null) {
                    result.put(cveId, entry.path("dateAdded").asText(null));
                }
            }
            return result;
        } catch (Exception e) {
            return Map.of();
        }
    }
}
