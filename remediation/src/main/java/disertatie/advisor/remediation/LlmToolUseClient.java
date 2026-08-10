package disertatie.advisor.remediation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/*
 * Abstractizează bucla de tool-use din peste orice furnizor LLM.
 */
public interface LlmToolUseClient {

    JsonNode sendMessages(ArrayNode messages, ArrayNode tools) throws Exception;

    default ObjectNode userMessage(String text) {
        ObjectNode msg = createObjectNode();
        msg.put("role", "user");
        ArrayNode content = createArrayNode();
        ObjectNode block = createObjectNode();
        block.put("type", "text");
        block.put("text", text);
        content.add(block);
        msg.set("content", content);
        return msg;
    }

    default ObjectNode assistantMessage(JsonNode responseContent) {
        ObjectNode msg = createObjectNode();
        msg.put("role", "assistant");
        msg.set("content", responseContent);
        return msg;
    }

    ArrayNode createArrayNode();

    ObjectNode createObjectNode();
}
