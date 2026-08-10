package disertatie.advisor.mavenplugin;

import java.util.List;

public record FixReportEntry(
        String module,
        String pomFile,
        String cveId,
        String componentPurl,
        String groupId,
        String artifactId,
        String currentVersion,
        String fixedVersion,
        String appliedVersion,
        double cvss,
        Double epssScore,
        boolean inKev,
        boolean direct,
        String path,
        String reachability,
        double score,
        String versionBumpCategory,
        String strategy,
        String state,
        String riskyReason,
        String verdict,
        String proposedSnippet,
        List<String> groupedWithCveIds,
        String error
) {}
