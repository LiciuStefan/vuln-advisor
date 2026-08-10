package disertatie.advisor.remediation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import disertatie.contracts.model.ScoredVulnerability;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * Agent LLM cu tool-use pentru remedierea vulnerabilităţilor.
 */
public class RemediationAgent {

    private static final int MAX_ITERATIONS = 10;
    private static final Pattern VERSION_TAG = Pattern.compile("<version>([^<]+)</version>");

    private final LlmToolUseClient llmToolUseClient;

    public RemediationAgent(LlmToolUseClient anthropic) {
        this.llmToolUseClient = anthropic;
    }

    /*
     * Rulează bucla tool-use pentru o singură vulnerabilitate, cu fişierul pom.xml
     * ţintă şi strategia de scriere explicite (folosit de plugin-ul Maven, unde
     * ţinta poate fi orice modul din reactor, nu doar rădăcina).
     */
    public String remediate(ScoredVulnerability scoredVulnerability, Path projectDir, FixTarget target) throws Exception {
        ArrayNode tools = buildToolDefinitions();
        ArrayNode messages = llmToolUseClient.createArrayNode();

        String userPrompt = buildPrompt(scoredVulnerability, projectDir, target);
        messages.add(llmToolUseClient.userMessage(userPrompt));

        boolean ranTests = false;

        for (int iteration = 0; iteration < MAX_ITERATIONS; iteration++) {
            JsonNode response = llmToolUseClient.sendMessages(messages, tools);
            String stopReason = response.path("stop_reason").asText("");
            JsonNode content = response.path("content");

            messages.add(llmToolUseClient.assistantMessage(content));

            if ("end_turn".equals(stopReason)) {
                String text = extractText(content);
                boolean claimsPass = text.toLowerCase().contains("pass");
                return (claimsPass && ranTests) ? "PASS" : "FAIL";
            }

            if (!"tool_use".equals(stopReason)) break;

            // Execută fiecare tool call şi colectează rezultatele
            boolean hasToolUse = false;
            for (JsonNode block : content) {
                if ("tool_use".equals(block.path("type").asText())) {
                    hasToolUse = true;
                    if ("run_tests".equals(block.path("name").asText())) {
                        ranTests = true;
                    }
                }
            }
            if (!hasToolUse) break;

            ObjectNode toolResultMsg = llmToolUseClient.createObjectNode();
            toolResultMsg.put("role", "user");
            toolResultMsg.set("content", collectToolResults(content, projectDir, target));
            messages.add(toolResultMsg);
        }

        return "FAIL";
    }

    private ArrayNode collectToolResults(JsonNode content, Path projectDir, FixTarget target) throws Exception {
        ArrayNode results = llmToolUseClient.createArrayNode();
        for (JsonNode block : content) {
            if (!"tool_use".equals(block.path("type").asText())) continue;
            String toolId   = block.path("id").asText();
            String toolName = block.path("name").asText();
            JsonNode input  = block.path("input");
            String result = executeTool(toolName, input, projectDir, target);

            ObjectNode resultBlock = llmToolUseClient.createObjectNode();
            resultBlock.put("type", "tool_result");
            resultBlock.put("tool_use_id", toolId);
            resultBlock.put("content", result);
            results.add(resultBlock);
        }
        return results;
    }

    private String executeTool(String toolName, JsonNode input, Path projectDir, FixTarget target) {
        return switch (toolName) {
            case "read_pom"       -> readPom(target.pomFile());
            case "apply_fix"      -> applyFix(
                    input.path("groupId").asText(),
                    input.path("artifactId").asText(),
                    input.path("newVersion").asText(),
                    target);
            case "run_tests"      -> runTests(projectDir);
            case "read_test_log"  -> readLog(projectDir);
            default               -> "Unknown tool " + toolName;
        };
    }

    private String readPom(Path pomFile) {
        try {
            return Files.readString(pomFile);
        } catch (IOException e) {
            return "Error while reading " + pomFile + ": " + e.getMessage();
        }
    }

    private String applyFix(String groupId, String artifactId, String newVersion, FixTarget target) {
        Path pom = target.pomFile();
        try {
            String content = Files.readString(pom);
            String updated = switch (target.strategy()) {
                case DEPENDENCY_MANAGEMENT_ADD ->
                        upsertDependencyManagement(content, groupId, artifactId, newVersion);
                case DEPENDENCY_MANAGEMENT_EDIT ->
                        updateVersionInDependencyManagementEntry(content, groupId, artifactId, newVersion);
                case DIRECT_VERSION -> updateVersionInPom(content, groupId, artifactId, newVersion);
            };
            if (updated.equals(content)) {
                return "WARN: no change for " + groupId + ":" + artifactId
                        + " in " + pom;
            }
            Files.writeString(pom, updated);
            return "OK: " + groupId + ":" + artifactId + " → " + newVersion
                    + " (" + pom + ", " + target.strategy() + ")";
        } catch (IOException e) {
            return "Error occurred while modifying " + pom + ": " + e.getMessage();
        }
    }

    private String runTests(Path projectDir) {
        Path logFile = projectDir.resolve("remediation-test.log");
        try {
            ProcessBuilder pb = new ProcessBuilder("mvn", "test", "--batch-mode", "-q");
            pb.directory(projectDir.toFile());
            pb.redirectOutput(logFile.toFile());
            pb.redirectError(ProcessBuilder.Redirect.appendTo(logFile.toFile()));

            Process p = pb.start();
            boolean done = p.waitFor(10, TimeUnit.MINUTES);
            if (!done) {
                p.destroyForcibly();
                return "TIMEOUT";
            }
            int exit = p.exitValue();
            String log = Files.exists(logFile) ? tail(Files.readString(logFile), 50) : "";
            return (exit == 0 ? "PASS" : "FAIL") + "\n" + log;
        } catch (Exception e) {
            return "Error while running the tests " + e.getMessage();
        }
    }

    private String readLog(Path projectDir) {
        Path logFile = projectDir.resolve("remediation-test.log");
        try {
            if (!Files.exists(logFile)) return "No log file found";
            return tail(Files.readString(logFile), 100);
        } catch (IOException e) {
            return "Error while reading log " + e.getMessage();
        }
    }

    public static String updateVersionInPom(String pomContent, String groupId, String artifactId, String newVersion) {
        // Pattern: găseşte blocul <dependency>...</dependency> care conţine ambele taguri
        String[] blocks = pomContent.split("(?=<dependency>)");
        StringBuilder result = new StringBuilder();
        for (String block : blocks) {
            if (block.contains("<groupId>" + groupId + "</groupId>")
                    && block.contains("<artifactId>" + artifactId + "</artifactId>")) {
                block = block.replaceAll(
                        "<version>[^<]+</version>",
                        "<version>" + newVersion + "</version>"
                );
            }
            result.append(block);
        }
        return result.toString();
    }

    /*
     * Adaugă sau actualizează un override de versiune în <dependencyManagement>,
     * pentru dependenţe tranzitive care nu apar ca <dependency> explicită în pom.
     * Creează secţiunea <dependencyManagement> dacă lipseşte
     */
    public static String upsertDependencyManagement(String pomContent, String groupId, String artifactId, String newVersion) {
        String dependencyBlock = "        <dependency>\n"
                + "            <groupId>" + groupId + "</groupId>\n"
                + "            <artifactId>" + artifactId + "</artifactId>\n"
                + "            <version>" + newVersion + "</version>\n"
                + "        </dependency>\n";

        int dependencyManagementTagStartIndex = pomContent.indexOf("<dependencyManagement>");
        if (dependencyManagementTagStartIndex >= 0) {
            int dependencyManagementTagEndIndex = pomContent.indexOf("</dependencyManagement>", dependencyManagementTagStartIndex);
            if (dependencyManagementTagEndIndex < 0) return pomContent;

            String dmBlock = pomContent.substring(dependencyManagementTagStartIndex, dependencyManagementTagEndIndex);
            if (dmBlock.contains("<groupId>" + groupId + "</groupId>")
                    && dmBlock.contains("<artifactId>" + artifactId + "</artifactId>")) {
                // deja override-uit — doar actualizăm versiunea existentă
                return updateVersionInPom(pomContent, groupId, artifactId, newVersion);
            }

            int depsOpen = pomContent.indexOf("<dependencies>", dependencyManagementTagStartIndex);
            if (depsOpen >= 0 && depsOpen < dependencyManagementTagEndIndex) {
                int insertAt = depsOpen + "<dependencies>".length();
                return pomContent.substring(0, insertAt) + "\n" + dependencyBlock
                        + pomContent.substring(insertAt);
            }

            int insertAt = pomContent.indexOf('>', dependencyManagementTagStartIndex) + 1;
            return pomContent.substring(0, insertAt)
                    + "\n    <dependencies>\n" + dependencyBlock + "    </dependencies>\n"
                    + pomContent.substring(insertAt);
        }

        String newSection = "    <dependencyManagement>\n"
                + "        <dependencies>\n" + dependencyBlock
                + "        </dependencies>\n"
                + "    </dependencyManagement>\n";

        int anchor = pomContent.indexOf("<dependencies>");
        if (anchor < 0) anchor = pomContent.indexOf("<build>");
        if (anchor < 0) anchor = pomContent.indexOf("</project>");
        if (anchor < 0) return pomContent;

        return pomContent.substring(0, anchor) + newSection + pomContent.substring(anchor);
    }

    public static String updateVersionInDependencyManagementEntry(
            String pomContent, String groupId, String artifactId, String newVersion) {
        int dependencyManagementTagStartIndex = pomContent.indexOf("<dependencyManagement>");
        if (dependencyManagementTagStartIndex < 0) return pomContent;
        int dependencyManagementTagEndIndex = pomContent.indexOf("</dependencyManagement>", dependencyManagementTagStartIndex);
        if (dependencyManagementTagEndIndex < 0) return pomContent;

        String dependencyManagementSection = pomContent.substring(dependencyManagementTagStartIndex, dependencyManagementTagEndIndex);
        String updatedSection = updateVersionInPom(dependencyManagementSection, groupId, artifactId, newVersion);
        return pomContent.substring(0, dependencyManagementTagStartIndex) + updatedSection + pomContent.substring(dependencyManagementTagEndIndex);
    }

    public static VersionEditability inlineVersionStatus(String pomContent, String groupId, String artifactId) {
        String[] blocks = stripDependencyManagement(pomContent).split("(?=<dependency>)");
        for (String block : blocks) {
            if (block.contains("<groupId>" + groupId + "</groupId>")
                    && block.contains("<artifactId>" + artifactId + "</artifactId>")) {
                Matcher matcher = VERSION_TAG.matcher(block);
                if (!matcher.find()) {
                    return hasLocalDependencyManagementEntry(pomContent, groupId, artifactId)
                            ? VersionEditability.MANAGED_LOCALLY
                            : VersionEditability.INHERITED;
                }
                return matcher.group(1).trim().startsWith("${") ? VersionEditability.PROPERTY : VersionEditability.INLINE;
            }
        }
        return hasLocalDependencyManagementEntry(pomContent, groupId, artifactId)
                ? VersionEditability.MANAGED_LOCALLY
                : VersionEditability.NOT_DECLARED;
    }

    private static boolean hasLocalDependencyManagementEntry(String pomContent, String groupId, String artifactId) {
        String dependencyManagementSection = extractDependencyManagementSection(pomContent);
        return !dependencyManagementSection.isEmpty() && versionInBlocks(dependencyManagementSection, groupId, artifactId) != null;
    }

    public static String currentVersion(String pomContent, String groupId, String artifactId) {
        String dependencyManagementVersion = versionInBlocks(extractDependencyManagementSection(pomContent), groupId, artifactId);
        if (dependencyManagementVersion != null) return dependencyManagementVersion;
        return versionInBlocks(stripDependencyManagement(pomContent), groupId, artifactId);
    }

    private static String versionInBlocks(String sectionText, String groupId, String artifactId) {
        String[] blocks = sectionText.split("(?=<dependency>)");
        for (String block : blocks) {
            if (block.contains("<groupId>" + groupId + "</groupId>")
                    && block.contains("<artifactId>" + artifactId + "</artifactId>")) {
                Matcher matcher = VERSION_TAG.matcher(block);
                if (matcher.find()) return matcher.group(1).trim();
            }
        }
        return null;
    }

    private static String extractDependencyManagementSection(String pomContent) {
        int start = pomContent.indexOf("<dependencyManagement>");
        if (start < 0) return "";
        int end = pomContent.indexOf("</dependencyManagement>", start);
        return end < 0 ? "" : pomContent.substring(start, end);
    }

    private static String stripDependencyManagement(String pomContent) {
        int start = pomContent.indexOf("<dependencyManagement>");
        if (start < 0) return pomContent;
        int end = pomContent.indexOf("</dependencyManagement>", start);
        if (end < 0) return pomContent;
        return pomContent.substring(0, start) + pomContent.substring(end + "</dependencyManagement>".length());
    }

    private String buildPrompt(ScoredVulnerability sv, Path projectDir, FixTarget target) {
        String riskContext = "";
        if (target.direct() != null) {
            StringBuilder sb = new StringBuilder();
            sb.append(switch (target.strategy()) {
                case DIRECT_VERSION -> "Dependenţă DIRECTĂ - fixul se aplică pe blocul <dependency> "
                        + "existent din pom-ul ţintă.";
                case DEPENDENCY_MANAGEMENT_EDIT -> "Dependenţă DIRECTĂ, dar fără <version> propriu la "
                        + "locul de folosire - versiunea e deja gestionată de o intrare existentă în "
                        + "<dependencyManagement> din ACELAŞI pom; fixul editează versiunea din ACEA "
                        + "intrare, nu adaugă una nouă şi nu atinge blocul <dependency> de la locul de "
                        + "folosire (care oricum n-are <version> propriu de editat).";
                case DEPENDENCY_MANAGEMENT_ADD -> "Dependenţă TRANZITIVĂ - nu apare ca <dependency> "
                        + "explicită în pom-ul ţintă; fixul trebuie aplicat ca override în "
                        + "<dependencyManagement>, care forţează versiunea oriunde apare artefactul în "
                        + "arbore, fără să adauge o dependenţă nouă la build.";
            });
            if (target.path() != null) {
                sb.append("\nCale în arborele de dependenţe: ").append(target.path());
            }
            if (target.versionBumpCategory() != null) {
                sb.append("\nTip de bump: ").append(target.versionBumpCategory());
                if ("MAJOR".equals(target.versionBumpCategory()) && Boolean.FALSE.equals(target.direct())) {
                    sb.append(" - risc compus (tranzitiv + major): versiunea forţată nu a fost "
                            + "testată de autorul dependinţei directe, iar suita de teste a proiectului "
                            + "poate să nu exercite calea internă care foloseşte artefactul vulnerabil. "
                            + "Fii explicit în raţionamentul final despre acest risc.");
                }
            }
            riskContext = "\n" + sb + "\n";
        }

        return String.format("""
                Eşti un agent de remediere pentru vulnerabilităţi Maven.

                Vulnerabilitate: %s
                Componentă afectată: %s (versiunea curentă: %s)
                CVSS: %.1f
                Versiunea care rezolvă vulnerabilitatea: %s
                Scor de risc calculat: %.1f
                %s
                Director proiect (pentru run_tests): %s
                Fişier pom.xml ţintă (pentru read_pom/apply_fix): %s

                Foloseşte uneltele disponibile pentru a:
                1. Citi pom.xml-ul ţintă
                2. Aplica versiunea de fix pentru dependenţa vulnerabilă, cu groupId/artifactId ale
                   COMPONENTEI VULNERABILE (nu ale dependenţei directe care o aduce)
                3. Rula testele şi verifica că nu există regresii
                4. Raporta PASS dacă testele trec sau FAIL dacă eşuează

                Raportează clar la final: PASS sau FAIL.
                """,
                sv.vulnerability().cveId(),
                sv.component().artifact(),
                sv.component().version(),
                sv.vulnerability().cvss(),
                sv.vulnerability().fixedVersion() != null ? sv.vulnerability().fixedVersion() : "necunoscută",
                sv.score(),
                riskContext,
                projectDir,
                target.pomFile()
        );
    }

    private ArrayNode buildToolDefinitions() {
        ArrayNode tools = llmToolUseClient.createArrayNode();
        tools.add(buildTool("read_pom",
                "Citeşte conţinutul fişierului pom.xml ţintă.",
                llmToolUseClient.createObjectNode().put("type", "object")
                        .set("properties", llmToolUseClient.createObjectNode())));
        tools.add(buildTool("apply_fix",
                "Modifică versiunea unei dependenţe în pom.xml-ul ţintă (direct sau prin "
                        + "dependencyManagement, în funcţie de context).",
                buildSchema("groupId", "artifactId", "newVersion")));
        tools.add(buildTool("run_tests",
                "Rulează mvn test şi returnează PASS sau FAIL cu ultimele linii din log.",
                llmToolUseClient.createObjectNode().put("type", "object")
                        .set("properties", llmToolUseClient.createObjectNode())));
        tools.add(buildTool("read_test_log",
                "Citeşte log-ul complet al ultimei rulări de teste.",
                llmToolUseClient.createObjectNode().put("type", "object")
                        .set("properties", llmToolUseClient.createObjectNode())));
        return tools;
    }

    private ObjectNode buildTool(String name, String description, ObjectNode inputSchema) {
        ObjectNode tool = llmToolUseClient.createObjectNode();
        tool.put("name", name);
        tool.put("description", description);
        tool.set("input_schema", inputSchema);
        return tool;
    }

    private ObjectNode buildSchema(String... fields) {
        ObjectNode schema = llmToolUseClient.createObjectNode();
        schema.put("type", "object");
        ObjectNode props = llmToolUseClient.createObjectNode();
        for (String field : fields) {
            props.set(field, llmToolUseClient.createObjectNode().put("type", "string"));
        }
        schema.set("properties", props);
        ArrayNode required = llmToolUseClient.createArrayNode();
        for (String field : fields) required.add(field);
        schema.set("required", required);
        return schema;
    }

    private String extractText(JsonNode content) {
        StringBuilder sb = new StringBuilder();
        for (JsonNode block : content) {
            if ("text".equals(block.path("type").asText())) {
                sb.append(block.path("text").asText());
            }
        }
        return sb.toString();
    }

    private String tail(String text, int lines) {
        String[] all = text.split("\n");
        int start = Math.max(0, all.length - lines);
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < all.length; i++) sb.append(all[i]).append("\n");
        return sb.toString();
    }
}
