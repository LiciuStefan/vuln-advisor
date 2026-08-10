package disertatie.advisor.mavenplugin;

import java.util.List;

public record FixReport(
        String generatedAt,
        boolean dryRun,
        double scoreThreshold,
        String llmProvider,
        int componentsAnalyzed,
        int vulnerabilitiesFound,
        int actionableVulnerabilities,
        List<String> skippedModules,
        List<FixReportEntry> entries
) {}
