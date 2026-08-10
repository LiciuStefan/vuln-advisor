package disertatie.advisor.matching;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import disertatie.contracts.model.ExploitSignal;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;

public class EpssClient {

    private static final String BASE_URL = "https://api.first.org/data/v1/epss";
    private static final int BATCH_SIZE = 100;

    private final HttpClient http;
    private final ObjectMapper mapper;

    public EpssClient(ObjectMapper mapper) {
        this.mapper = mapper;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .build();
    }

    public Map<String, ExploitSignal> fetchScores(Collection<String> cveIds) {
        List<String> ids = new ArrayList<>(new LinkedHashSet<>(cveIds));
        Map<String, ExploitSignal> out = new HashMap<>();

        for (int i = 0; i < ids.size(); i += BATCH_SIZE) {
            List<String> batch = ids.subList(i, Math.min(i + BATCH_SIZE, ids.size()));
            try {
                fetchBatch(batch, out);
            } catch (Exception e) {

            }
        }
        return out;
    }

    private void fetchBatch(List<String> cveIds, Map<String, ExploitSignal> out) throws Exception {
        String cveParam = String.join(",", cveIds);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "?cve=" + cveParam))
                .timeout(Duration.ofSeconds(20))
                .GET()
                .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) return;

        JsonNode data = mapper.readTree(resp.body()).path("data");
        for (JsonNode entry : data) {
            String cve = entry.path("cve").asText(null);
            if (cve == null) continue;
            double epss = entry.path("epss").asDouble(0.0);
            double percentile = entry.path("percentile").asDouble(0.0);
            out.put(cve, new ExploitSignal(cve, epss, percentile, false, null));
        }
    }
}
