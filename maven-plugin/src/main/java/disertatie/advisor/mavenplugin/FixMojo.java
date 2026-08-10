package disertatie.advisor.mavenplugin;

import com.fasterxml.jackson.databind.ObjectMapper;
import disertatie.advisor.matching.EpssClient;
import disertatie.advisor.matching.KevCatalog;
import disertatie.advisor.matching.MatchingService;
import disertatie.advisor.matching.OsvClient;
import disertatie.advisor.prioritization.ScoreOutput;
import disertatie.advisor.prioritization.ScoringEngine;
import disertatie.advisor.prioritization.WeightConfig;
import disertatie.advisor.reachability.CallGraphBuilder;
import disertatie.advisor.reachability.ReachabilityService;
import disertatie.advisor.remediation.*;
import disertatie.contracts.model.Component;
import disertatie.contracts.model.ExploitSignal;
import disertatie.contracts.model.MatchedVulnerability;
import disertatie.contracts.model.Reachability;
import disertatie.contracts.model.ScoredVulnerability;
import disertatie.contracts.model.Vulnerability;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.DefaultProjectBuildingRequest;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectBuildingRequest;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilder;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilderException;
import org.apache.maven.shared.dependency.graph.DependencyNode;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

/**
 * Goal `fix`: analizează şi remediază vulnerabilităţi direct în reactor-ul Maven al
 * proiectului ţintă.
 *
 */
@Mojo(name = "fix", aggregator = true, requiresDependencyResolution = ResolutionScope.TEST,
        defaultPhase = LifecyclePhase.VERIFY)
public class FixMojo extends AbstractMojo {

    @Parameter(defaultValue = "${session}", readonly = true, required = true)
    private MavenSession session;

    @Parameter(defaultValue = "${reactorProjects}", readonly = true, required = true)
    private List<MavenProject> reactorProjects;

    @Parameter(property = "llmProvider", defaultValue = "gemini")
    private String llmProvider;

    @Parameter(property = "anthropicApiKey", defaultValue = "${env.ANTHROPIC_API_KEY}")
    private String anthropicApiKey;

    @Parameter(property = "anthropicModel", defaultValue = "claude-sonnet-4-6")
    private String anthropicModel;

    @Parameter(property = "geminiApiKey", defaultValue = "${env.GEMINI_API_KEY}")
    private String geminiApiKey;

    @Parameter(property = "geminiModel", defaultValue = disertatie.advisor.remediation.GeminiClient.DEFAULT_MODEL)
    private String geminiModel;

    @Parameter(property = "dryRun", defaultValue = "false")
    private boolean dryRun;

    @Parameter(property = "scoreThreshold", defaultValue = "50")
    private double scoreThreshold;

    @org.apache.maven.plugins.annotations.Component
    private DependencyGraphBuilder dependencyGraphBuilder;

    @org.apache.maven.plugins.annotations.Component
    private RepositorySystem repositorySystem;

    private final ObjectMapper mapper = new ObjectMapper();
    private final ReachabilityService reachabilityService = new ReachabilityService(new CallGraphBuilder());

    // Grouping all the CVE's based on a multi-key: module, groupId, artifactId
    private record GroupKey(MavenProject module, String groupId, String artifactId) {}

    private record GroupMember(MatchedVulnerability matchedVulnerability, Occurrence occurrence, double score) {}

    @Override
    public void execute() throws MojoExecutionException {
        Log log = getLog();

        Map<MavenProject, DependencyNode> graphByModule = new LinkedHashMap<>();
        Map<String, List<Occurrence>> occurrencesByPurl = new LinkedHashMap<>();
        List<String> skippedModules = new ArrayList<>();

        for (MavenProject module : reactorProjects) {
            DependencyNode root;
            try {
                root = buildGraph(module);
            } catch (DependencyGraphBuilderException e) {
                String reason = module.getArtifactId() + ": " + e.getMessage();
                log.warn("The dependency graph could not be built: " + reason);
                skippedModules.add(reason);
                continue;
            }
            graphByModule.put(module, root);
            for (Occurrence occurrence : ReactorDependencyGraph.compute(module, root)) {
                occurrencesByPurl.computeIfAbsent(occurrence.component().purl(), key -> new ArrayList<>()).add(occurrence);
            }
        }

        if (occurrencesByPurl.isEmpty()) {
            log.info("There are no dependencies in the dependency graph");
            writeReport(List.of(), 0, 0, 0, skippedModules);
            return;
        }

        List<Component> components = pickRepresentative(occurrencesByPurl);
        log.info("Unique components from the reactor: " + components.size());

        List<MatchedVulnerability> matched;
        try {
            MatchingService matchingService = new MatchingService(
                    new OsvClient(mapper), new EpssClient(mapper), new KevCatalog(mapper));
            matched = matchingService.match(components);
        } catch (Exception e) {
            throw new MojoExecutionException("(OSV/EPSS/KEV) vulnerability correlation has failed", e);
        }
        log.info("Found vulnerabilities: " + matched.size());

        if (matched.isEmpty()) {
            writeReport(List.of(), components.size(), 0, 0, skippedModules);
            return;
        }

        Map<String, Reachability> reachabilityByPurl =
                computeReachability(matched, occurrencesByPurl, graphByModule, log);

        // O singură apariţie per (modul, purl) - cea cu adâncimea minimă - elimină
        // duplicatele de tip "diamond" (acelaşi artefact adus de 2 dependenţe directe
        // diferite ale aceluiaşi modul)
        Map<String, Map<MavenProject, Occurrence>> occurrenceByPurlAndModule =
                dedupeByModule(occurrencesByPurl);

        WeightConfig weights = WeightConfig.defaults().withActionThreshold(scoreThreshold);

        List<FixReportEntry> entries = new ArrayList<>();
        Map<GroupKey, List<GroupMember>> fixGroups = new LinkedHashMap<>();

        for (MatchedVulnerability matchedVulnerability : matched) {
            String purl = matchedVulnerability.component().purl();
            Map<MavenProject, Occurrence> byModule =
                    occurrenceByPurlAndModule.getOrDefault(purl, Map.of());
            Reachability reach = reachabilityByPurl.getOrDefault(purl, Reachability.UNDETERMINED);

            if (byModule.isEmpty()) {
                entries.add(notActionableEntry(matchedVulnerability, null, 0.0, reach));
                continue;
            }

            for (Occurrence occurence : byModule.values()) {
                // Scorul se calculează per ocurenţă
                // direct/depth diferă între module, deci şi scorul trebuie să difere.
                ScoreOutput out = ScoringEngine.score(
                        occurence.component(), matchedVulnerability.vulnerability(), matchedVulnerability.exploitSignal(), reach, weights);

                if (out.score() < scoreThreshold || matchedVulnerability.vulnerability().fixedVersion() == null) {
                    entries.add(notActionableEntry(matchedVulnerability, occurence, out.score(), reach));
                    continue;
                }

                GroupKey key = new GroupKey(occurence.module(), occurence.component().group(), occurence.component().artifact());
                fixGroups.computeIfAbsent(key, groupKey -> new ArrayList<>())
                        .add(new GroupMember(matchedVulnerability, occurence, out.score()));
            }
        }

        LlmToolUseClient llmClient = buildLlmClient();
        RemediationAgent agent = new RemediationAgent(llmClient);
        log.info("LLM provider: " + llmProvider);

        int actionable = 0;
        for (List<GroupMember> members : fixGroups.values()) {
            actionable += members.size();
            entries.addAll(processGroup(members, agent, reachabilityByPurl, log));
        }

        writeReport(entries, components.size(), matched.size(), actionable, skippedModules);
    }

    private LlmToolUseClient buildLlmClient() {
        if ("anthropic".equalsIgnoreCase(llmProvider)) {
            return new AnthropicClient(mapper, anthropicApiKey, anthropicModel);
        }
        return new GeminiClient(mapper, geminiApiKey, geminiModel);
    }

    private DependencyNode buildGraph(MavenProject module) throws DependencyGraphBuilderException {
        ProjectBuildingRequest buildingRequest =
                new DefaultProjectBuildingRequest(session.getProjectBuildingRequest());
        buildingRequest.setProject(module);
        return dependencyGraphBuilder.buildDependencyGraph(buildingRequest, null);
    }

    // Pentru matching alegem o singură reprezentare per purl: preferăm direct, apoi adâncimea minimă
    private List<Component> pickRepresentative(Map<String, List<Occurrence>> byPurl) {
        List<Component> result = new ArrayList<>();
        for (List<Occurrence> occurrences : byPurl.values()) {
            Component best = occurrences.stream()
                    .map(Occurrence::component)
                    .min(Comparator.comparing(Component::direct).reversed()
                            .thenComparingInt(Component::depth))
                    .orElseThrow();
            result.add(best);
        }
        return result;
    }

    private Map<String, Map<MavenProject, Occurrence>> dedupeByModule(
            Map<String, List<Occurrence>> occurrencesByPurl) {
        Map<String, Map<MavenProject, Occurrence>> result = new LinkedHashMap<>();
        for (Map.Entry<String, List<Occurrence>> occurrenceByPurl : occurrencesByPurl.entrySet()) {
            Map<MavenProject, Occurrence> byModule = new LinkedHashMap<>();
            for (Occurrence occurrence : occurrenceByPurl.getValue()) {
                byModule.merge(occurrence.module(), occurrence,
                        (firstOccurrence, secondOccurrence) -> firstOccurrence.component().depth() <= secondOccurrence.component().depth() ? firstOccurrence : secondOccurrence);
            }
            result.put(occurrenceByPurl.getKey(), byModule);
        }
        return result;
    }

    private Map<String, Reachability> computeReachability(List<MatchedVulnerability> matched,
            Map<String, List<Occurrence>> occurrencesByPurl,
            Map<MavenProject, DependencyNode> graphByModule, Log log) {

        Map<String, Reachability> result = new HashMap<>();
        Set<String> vulnPurls = matched.stream().map(matchedVuln -> matchedVuln.component().purl()).collect(Collectors.toSet());

        Map<MavenProject, Set<String>> purlsByModule = new LinkedHashMap<>();
        for (String purl : vulnPurls) {
            for (Occurrence occurrence : occurrencesByPurl.getOrDefault(purl, List.of())) {
                purlsByModule.computeIfAbsent(occurrence.module(), mavenProject -> new LinkedHashSet<>()).add(purl);
            }
        }

        Map<String, Component> componentByPurl = new HashMap<>();
        for (MatchedVulnerability matchedVuln : matched) {
            componentByPurl.put(matchedVuln.component().purl(), matchedVuln.component());
        }

        for (Map.Entry<MavenProject, Set<String>> entry : purlsByModule.entrySet()) {
            MavenProject module = entry.getKey();
            DependencyNode root = graphByModule.get(module);
            Path appClasses = module.getBasedir().toPath().resolve("target").resolve("classes");

            if (!Files.isDirectory(appClasses)) {
                log.info(module.getArtifactId()
                        + ": target/classes is missing, compile the project (mvn compile) for a real "
                        + "reachability signal");
                markUndetermined(result, entry.getValue());
                continue;
            }

            List<Path> depJars = resolveAllArtifactFiles(module, root, log);
            if (depJars.isEmpty()) {
                markUndetermined(result, entry.getValue());
                continue;
            }

            Map<String, Set<String>> vulnerableClassesByPurl = new LinkedHashMap<>();
            for (String purl : entry.getValue()) {
                vulnerableClassesByPurl.put(purl, classesOfComponent(module, root, componentByPurl.get(purl), log));
            }

            Map<String, Reachability> moduleResult;
            try {
                moduleResult = reachabilityService.reachabilityForModule(appClasses, depJars, vulnerableClassesByPurl);
            } catch (Exception e) {
                log.warn("The call graph has failed to be built: " + module.getArtifactId()
                        + ": " + e.getMessage());
                markUndetermined(result, entry.getValue());
                continue;
            }

            for (Map.Entry<String, Reachability> moduleEntry : moduleResult.entrySet()) {
                result.merge(moduleEntry.getKey(), moduleEntry.getValue(), ReachabilityService::combine);
            }
        }

        for (String purl : vulnPurls) {
            result.putIfAbsent(purl, Reachability.UNDETERMINED);
        }
        return result;
    }

    private void markUndetermined(Map<String, Reachability> result, Set<String> purls) {
        for (String purl : purls) {
            result.merge(purl, Reachability.UNDETERMINED, ReachabilityService::combine);
        }
    }

    private List<Path> resolveAllArtifactFiles(MavenProject module, DependencyNode root, Log log) {
        List<Path> result = new ArrayList<>();
        Deque<DependencyNode> stack = new ArrayDeque<>(childrenOf(root));
        while (!stack.isEmpty()) {
            DependencyNode node = stack.pop();
            stack.addAll(childrenOf(node));
            Path jar = resolveArtifactFile(module, node.getArtifact(), log);
            if (jar != null) {
                result.add(jar);
            }
        }
        return result;
    }

    private DependencyNode findNode(DependencyNode root, Component component) {
        Deque<DependencyNode> stack = new ArrayDeque<>(childrenOf(root));
        while (!stack.isEmpty()) {
            DependencyNode node = stack.pop();
            Artifact a = node.getArtifact();
            if (component.group().equals(a.getGroupId())
                    && component.artifact().equals(a.getArtifactId())
                    && component.version().equals(a.getVersion())) {
                return node;
            }
            stack.addAll(childrenOf(node));
        }
        return null;
    }

    private List<DependencyNode> childrenOf(DependencyNode node) {
        List<DependencyNode> children = node.getChildren();
        return children != null ? children : List.of();
    }


    private Set<String> classesOfComponent(MavenProject module, DependencyNode root, Component component, Log log) {
        if (component == null) return Set.of();
        DependencyNode node = findNode(root, component);
        if (node == null) return Set.of();
        Path jar = resolveArtifactFile(module, node.getArtifact(), log);
        if (jar == null) return Set.of();
        return extractClassNames(jar);
    }

    private Path resolveArtifactFile(MavenProject module, Artifact artifact, Log log) {
        if (artifact.getFile() != null) return artifact.getFile().toPath();
        try {
            org.eclipse.aether.artifact.Artifact aetherArtifact = new org.eclipse.aether.artifact.DefaultArtifact(
                    artifact.getGroupId(), artifact.getArtifactId(), artifact.getClassifier(),
                    "jar", artifact.getVersion());
            ArtifactRequest request = new ArtifactRequest(
                    aetherArtifact, module.getRemoteProjectRepositories(), null);
            ArtifactResult resolved = repositorySystem.resolveArtifact(session.getRepositorySession(), request);
            return resolved.getArtifact().getFile() != null ? resolved.getArtifact().getFile().toPath() : null;
        } catch (Exception e) {
            log.debug("The artifact could not be resolved: " + artifact + ": " + e.getMessage());
            return null;
        }
    }

    private Set<String> extractClassNames(Path jarPath) {
        Set<String> classes = new HashSet<>();
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            jar.stream()
                    .filter(e -> e.getName().endsWith(".class") && !e.getName().contains("$"))
                    .map(e -> e.getName().replace('/', '.').replace(".class", ""))
                    .forEach(classes::add);
        } catch (IOException e) {
            return Set.of();
        }
        return classes;
    }

    /*
     * Procesează toate CVE-urile de pe aceeaşi (modul, groupId, artifactId) ca un singur
     * fix la cea mai mare versiune de fix cerută dintre ele cu o singură scriere +
     * un singur run_tests
     */
    private List<FixReportEntry> processGroup(List<GroupMember> members, RemediationAgent agent,
            Map<String, Reachability> reachabilityByPurl, Log log) {

        GroupMember representative = members.stream()
                .max(Comparator.comparingDouble(GroupMember::score))
                .orElseThrow();
        String effectiveFixedVersion = members.stream()
                .map(groupMember -> groupMember.matchedVulnerability.vulnerability().fixedVersion())
                .max(VersionBumpClassifier::compare)
                .orElseThrow();

        Occurrence occ = representative.occurrence();
        VersionBumpClassifier.Category bump =
                VersionBumpClassifier.classify(occ.component().version(), effectiveFixedVersion);

        boolean risky = !occ.component().direct() && bump == VersionBumpClassifier.Category.MAJOR;
        String riskyReason = risky ? "transitive_major_bump" : null;

        VersionEditability editability = readEditability(
                occ.module().getFile().toPath(), occ.component().group(), occ.component().artifact(), log);

        if (!risky) {
            switch (editability) {
                case INHERITED -> {
                    risky = true;
                    riskyReason = "inherited_version";
                }
                case NOT_DECLARED -> {
                    risky = true;
                    riskyReason = "not_declared_in_pom";
                }
                case INLINE, PROPERTY, MANAGED_LOCALLY -> {
                }
            }
        }

        PomFixWriter.Fix fix = PomFixWriter.resolveFix(occ, effectiveFixedVersion, editability);
        String snippet = PomFixWriter.snippet(fix);

        String state;
        String verdict = null;
        String error = null;

        String appliedVersion = effectiveFixedVersion;

        if (risky) {
            state = "in_triage";
        } else if (dryRun) {
            state = "would_apply";
        } else {
            Vulnerability consolidatedVuln = new Vulnerability(
                    representative.matchedVulnerability().vulnerability().cveId(),
                    representative.matchedVulnerability().vulnerability().affectedPurl(),
                    representative.matchedVulnerability().vulnerability().affectedRange(),
                    effectiveFixedVersion,
                    representative.matchedVulnerability().vulnerability().cvss(),
                    representative.matchedVulnerability().vulnerability().cvssVector());
            ScoredVulnerability syntheticSv = new ScoredVulnerability(
                    occ.component(), consolidatedVuln,
                    reachabilityByPurl.getOrDefault(occ.component().purl(), Reachability.UNDETERMINED),
                    representative.score(), Map.of(), Map.of());
            FixTarget target = new FixTarget(fix.pomFile(), fix.strategy(),
                    occ.component().direct(), occ.component().path(), bump.name());
            try {
                verdict = agent.remediate(syntheticSv, occ.module().getBasedir().toPath(), target);
            } catch (Exception e) {
                verdict = "FAIL";
                error = e.getMessage();
                log.warn("Failed remediation for " + occ.component().group() + ":" + occ.component().artifact()
                        + " in " + occ.module().getArtifactId() + ": " + error);
            }
            state = "PASS".equals(verdict) ? "resolved" : "attempted";
            appliedVersion = readActualVersion(fix, log).orElse(effectiveFixedVersion);
        }

        List<FixReportEntry> result = new ArrayList<>();
        for (GroupMember member : members) {
            List<String> siblings = members.size() > 1
                    ? members.stream()
                            .map(groupMember -> groupMember.matchedVulnerability().vulnerability().cveId())
                            .filter(id -> !id.equals(member.matchedVulnerability().vulnerability().cveId()))
                            .toList()
                    : List.of();

            ExploitSignal signal = member.matchedVulnerability().exploitSignal();
            result.add(new FixReportEntry(
                    occ.module().getArtifactId(), occ.module().getFile().toString(),
                    member.matchedVulnerability().vulnerability().cveId(), occ.component().purl(),
                    occ.component().group(), occ.component().artifact(), occ.component().version(),
                    member.matchedVulnerability().vulnerability().fixedVersion(), appliedVersion,
                    member.matchedVulnerability().vulnerability().cvss(),
                    signal != null ? signal.epssScore() : null, signal != null && signal.inKev(),
                    occ.component().direct(), occ.component().path(),
                    reachabilityByPurl.getOrDefault(occ.component().purl(), Reachability.UNDETERMINED).name(),
                    member.score(), bump.name(), strategyLabel(fix.strategy()),
                    state, riskyReason, verdict, snippet, siblings, error));
        }
        return result;
    }

    private java.util.Optional<String> readActualVersion(PomFixWriter.Fix fix, Log log) {
        try {
            String pomText = Files.readString(fix.pomFile());
            return java.util.Optional.ofNullable(
                    RemediationAgent.currentVersion(pomText, fix.groupId(), fix.artifactId()));
        } catch (IOException e) {
            log.debug("Can not read from file: " + fix.pomFile() + " for version: " + e.getMessage());
            return java.util.Optional.empty();
        }
    }

    private VersionEditability readEditability(
            Path pomFile, String groupId, String artifactId, Log log) {
        try {
            String pomText = Files.readString(pomFile);
            return RemediationAgent.inlineVersionStatus(pomText, groupId, artifactId);
        } catch (IOException e) {
            log.warn("Can not read " + pomFile + " to verify version editability: "
                    + e.getMessage());
            return VersionEditability.NOT_DECLARED;
        }
    }

    private static String strategyLabel(WriteStrategy strategy) {
        return switch (strategy) {
            case DIRECT_VERSION -> "direct_version";
            case DEPENDENCY_MANAGEMENT_EDIT -> "dependency_management_local";
            case DEPENDENCY_MANAGEMENT_ADD -> "dependency_management";
        };
    }

    private FixReportEntry notActionableEntry(MatchedVulnerability mv, Occurrence occ,
            double score, Reachability reach) {
        Component c = occ != null ? occ.component() : mv.component();
        ExploitSignal signal = mv.exploitSignal();
        return new FixReportEntry(
                occ != null ? occ.module().getArtifactId() : null,
                occ != null ? occ.module().getFile().toString() : null,
                mv.vulnerability().cveId(), c.purl(), c.group(), c.artifact(), c.version(),
                mv.vulnerability().fixedVersion(), null, mv.vulnerability().cvss(),
                signal != null ? signal.epssScore() : null, signal != null && signal.inKev(),
                c.direct(), c.path(), reach != null ? reach.name() : null, score,
                null, null, "not_actionable", null, null, null, List.of(), null);
    }

    private void writeReport(List<FixReportEntry> entries, int componentsAnalyzed,
            int vulnerabilitiesFound, int actionable, List<String> skippedModules) throws MojoExecutionException {
        FixReport report = new FixReport(Instant.now().toString(), dryRun, scoreThreshold, llmProvider,
                componentsAnalyzed, vulnerabilitiesFound, actionable, skippedModules, entries);

        MavenProject rootProject = session.getTopLevelProject();
        Path targetDir = rootProject.getBasedir().toPath().resolve("target");
        Path reportFile = targetDir.resolve("vuln-advisor-report.json");
        try {
            Files.createDirectories(targetDir);
            mapper.writerWithDefaultPrettyPrinter().writeValue(reportFile.toFile(), report);
            getLog().info("Report written in " + reportFile);
        } catch (IOException e) {
            throw new MojoExecutionException("Can not write report " + reportFile, e);
        }
    }
}
