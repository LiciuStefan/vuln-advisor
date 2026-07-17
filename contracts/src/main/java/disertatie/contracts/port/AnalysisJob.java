package disertatie.contracts.port;

import java.util.UUID;

public record AnalysisJob(UUID analysisRunId, String repoUrl, String commit) {}
