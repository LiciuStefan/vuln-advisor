package disertatie.contracts.port;

import java.util.UUID;

/**
 * Trimis de orchestrator fiecărui worker. repoUrl/commit sunt populate
 * doar pentru etapa ingestion; pentru restul sunt null.
 */
public record StageTask(
        UUID analysisRunId,
        String stage,
        int attempt,
        String repoUrl,
        String commit
) {
    public static StageTask first(UUID analysisRunId, String stage) {
        return new StageTask(analysisRunId, stage, 1, null, null);
    }

    public static StageTask firstForRepo(UUID analysisRunId, String stage,
                                         String repoUrl, String commit) {
        return new StageTask(analysisRunId, stage, 1, repoUrl, commit);
    }

    public StageTask retry() {
        return new StageTask(analysisRunId, stage, attempt + 1, repoUrl, commit);
    }
}
