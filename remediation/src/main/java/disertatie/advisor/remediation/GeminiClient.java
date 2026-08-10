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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;

/*
 * Client HTTP Gemini API
 *
 */
public class GeminiClient implements LlmToolUseClient {

    private static final String API_BASE = "https://generativelanguage.googleapis.com/v1beta/models/";
    private static final int MAX_ATTEMPTS = 3;

    public static final String DEFAULT_MODEL = "gemini-flash-latest";

    private final ObjectMapper mapper;
    private final String apiKey;
    private final String model;
    private final HttpClient http;

    public GeminiClient(ObjectMapper mapper, String apiKey, String model) {
        this.mapper = mapper;
        this.apiKey = apiKey;
        this.model = (model != null && !model.isBlank()) ? model : DEFAULT_MODEL;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();
    }

    @Override
    public JsonNode sendMessages(ArrayNode messages, ArrayNode tools) throws Exception {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException("The api key is not configured");
        }

        ObjectNode body = mapper.createObjectNode();
        body.set("contents", toGeminiContents(messages));
        body.set("tools", toGeminiTools(tools));

        String url = API_BASE + model + ":generateContent";
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .header("x-goog-api-key", apiKey)
                .timeout(Duration.ofSeconds(120))
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                .build();

        Exception lastError = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() == 200) {
                    return fromGeminiResponse(mapper.readTree(resp.body()));
                }
                if (!isRetryable(resp.statusCode()) || attempt == MAX_ATTEMPTS) {
                    throw new RuntimeException("Gemini API error " + resp.statusCode() + ": " + resp.body());
                }
                lastError = new RuntimeException("Gemini API error " + resp.statusCode() + ": " + resp.body());
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

    ArrayNode toGeminiContents(ArrayNode messages) {
        Map<String, String> toolNameByUseId = new HashMap<>();
        for (JsonNode msg : messages) {
            for (JsonNode block : msg.path("content")) {
                if ("tool_use".equals(block.path("type").asText())) {
                    toolNameByUseId.put(block.path("id").asText(), block.path("name").asText());
                }
            }
        }

        ArrayNode contents = mapper.createArrayNode();
        for (JsonNode msg : messages) {
            String role = "assistant".equals(msg.path("role").asText()) ? "model" : "user";
            ArrayNode parts = mapper.createArrayNode();
            for (JsonNode block : msg.path("content")) {
                switch (block.path("type").asText()) {
                    case "text" -> parts.add(mapper.createObjectNode().put("text", block.path("text").asText()));
                    case "tool_use" -> parts.add(toFunctionCallPart(block));
                    case "tool_result" -> parts.add(toFunctionResponsePart(block, toolNameByUseId));
                    default -> { /* ignorăm blocuri necunoscute */ }
                }
            }
            if (parts.isEmpty()) continue; // Gemini respinge un content fără nicio parte
            ObjectNode content = mapper.createObjectNode();
            content.put("role", role);
            content.set("parts", parts);
            contents.add(content);
        }
        return contents;
    }

    private ObjectNode toFunctionCallPart(JsonNode toolUseBlock) {
        ObjectNode functionCall = mapper.createObjectNode();
        functionCall.put("name", toolUseBlock.path("name").asText());
        functionCall.set("args", toolUseBlock.path("input"));
        if (toolUseBlock.has("id")) {
            functionCall.put("id", toolUseBlock.path("id").asText());
        }

        ObjectNode part = mapper.createObjectNode();
        part.set("functionCall", functionCall);
        if (toolUseBlock.has("_geminiThoughtSignature")) {
            part.put("thoughtSignature", toolUseBlock.path("_geminiThoughtSignature").asText());
        }
        return part;
    }

    private ObjectNode toFunctionResponsePart(JsonNode toolResultBlock, Map<String, String> toolNameByUseId) {
        String toolUseId = toolResultBlock.path("tool_use_id").asText();
        String name = toolNameByUseId.getOrDefault(toolUseId, "unknown_tool");

        ObjectNode response = mapper.createObjectNode();
        response.put("content", toolResultBlock.path("content").asText());

        ObjectNode functionResponse = mapper.createObjectNode();
        functionResponse.put("name", name);
        // Gemini corelează functionResponse cu functionCall-ul original prin "id" —
        if (!toolUseId.isBlank()) {
            functionResponse.put("id", toolUseId);
        }
        functionResponse.set("response", response);

        ObjectNode part = mapper.createObjectNode();
        part.set("functionResponse", functionResponse);
        return part;
    }

    ArrayNode toGeminiTools(ArrayNode anthropicTools) {
        ArrayNode functionDeclarations = mapper.createArrayNode();
        for (JsonNode tool : anthropicTools) {
            ObjectNode decl = mapper.createObjectNode();
            decl.put("name", tool.path("name").asText());
            decl.put("description", tool.path("description").asText());
            JsonNode schema = tool.path("input_schema");
            if (schema.isObject()) {
                decl.set("parameters", toGeminiSchema(schema));
            }
            functionDeclarations.add(decl);
        }
        ArrayNode tools = mapper.createArrayNode();
        ObjectNode toolsEntry = mapper.createObjectNode();
        toolsEntry.set("functionDeclarations", functionDeclarations);
        tools.add(toolsEntry);
        return tools;
    }

    private JsonNode toGeminiSchema(JsonNode schema) {
        ObjectNode copy = schema.deepCopy();

        JsonNode typeNode = copy.get("type");
        if (typeNode != null && typeNode.isTextual()) {
            copy.put("type", typeNode.asText().toUpperCase(Locale.ROOT));
        }

        JsonNode properties = copy.get("properties");
        if (properties != null && properties.isObject()) {
            ObjectNode translatedProps = mapper.createObjectNode();
            Iterator<Map.Entry<String, JsonNode>> fields = properties.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                translatedProps.set(field.getKey(), toGeminiSchema(field.getValue()));
            }
            copy.set("properties", translatedProps);
        }

        return copy;
    }

    JsonNode fromGeminiResponse(JsonNode geminiResponse) {
        JsonNode candidates = geminiResponse.path("candidates");
        if (!candidates.isArray() || candidates.isEmpty()) {
            throw new RuntimeException("Gemini did not return any candidate" + geminiResponse);
        }

        JsonNode parts = candidates.path(0).path("content").path("parts");
        ArrayNode content = mapper.createArrayNode();
        boolean hasFunctionCall = false;
        int callIndex = 0;

        for (JsonNode part : parts) {
            if (part.has("text")) {
                content.add(mapper.createObjectNode().put("type", "text").put("text", part.path("text").asText()));
            } else if (part.has("functionCall")) {
                hasFunctionCall = true;
                JsonNode functionCall = part.path("functionCall");
                String id = functionCall.has("id") && !functionCall.path("id").asText().isBlank()
                        ? functionCall.path("id").asText()
                        : "call_" + (callIndex++) + "_" + functionCall.path("name").asText();

                ObjectNode block = mapper.createObjectNode();
                block.put("type", "tool_use");
                block.put("id", id);
                block.put("name", functionCall.path("name").asText());
                block.set("input", functionCall.path("args"));
                if (part.has("thoughtSignature")) {
                    block.put("_geminiThoughtSignature", part.path("thoughtSignature").asText());
                }
                content.add(block);
            }
        }

        ObjectNode result = mapper.createObjectNode();
        result.put("stop_reason", hasFunctionCall ? "tool_use" : "end_turn");
        result.set("content", content);
        return result;
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
