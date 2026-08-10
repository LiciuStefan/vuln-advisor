package disertatie.advisor.remediation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/*
 * Client HTTP Anthropic Messages API.
 * tool-use
 */
public class AnthropicClient implements LlmToolUseClient {

    private static final String API_URL = "https://api.anthropic.com/v1/messages";
    private static final String API_VERSION = "2023-06-01";
    private static final int MAX_ATTEMPTS = 3;

    private final String apiKey;
    private final String model;
    private final HttpClient http;
    private final ObjectMapper mapper;

    public AnthropicClient(ObjectMapper mapper, String apiKey, String model) {
        this.mapper = mapper;
        this.apiKey = apiKey;
        this.model = (model != null && !model.isBlank()) ? model : "claude-sonnet-4-6";
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();
    }

    /*
     * Trimite o listă de mesaje (cu tool definitions) şi returnează răspunsul.
     */
    @Override
    public JsonNode sendMessages(ArrayNode messages, ArrayNode tools) throws Exception {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException("There is no api key configured");
        }

        ObjectNode body = mapper.createObjectNode();
        body.put("model", model);
        body.put("max_tokens", 4096);
        body.set("tools", tools);
        body.set("messages", messages);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(API_URL))
                .header("Content-Type", "application/json")
                .header("x-api-key", apiKey)
                .header("anthropic-version", API_VERSION)
                .timeout(Duration.ofSeconds(120))
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                .build();

        Exception lastError = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() == 200) {
                    return mapper.readTree(resp.body());
                }
                if (!isRetryable(resp.statusCode()) || attempt == MAX_ATTEMPTS) {
                    throw new RuntimeException("Anthropic API error " + resp.statusCode() + ": " + resp.body());
                }
                lastError = new RuntimeException("Anthropic API error " + resp.statusCode() + ": " + resp.body());
            } catch (IOException e) {
                if (attempt == MAX_ATTEMPTS) throw e;
                lastError = e;
            }
            Thread.sleep(1000L * attempt);
        }
        throw lastError;
    }

    private boolean isRetryable(int statusCode) {
        return statusCode == 429 || statusCode >= 500;
    }

    @Override
    public ArrayNode createArrayNode() {
        return mapper.createArrayNode();
    }

    @Override
    public ObjectNode createObjectNode() {
        return mapper.createObjectNode();
    }
}
