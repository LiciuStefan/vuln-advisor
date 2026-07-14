package disertatie.contracts.port;

/**
 * Trimis de orchestrator fiecărui worker. repoUrl/commit sunt populate
 * doar pentru etapa ingestion; pentru restul sunt null.
 */
public record StageTask(
        String analysisRunId,
        String stage,
        int attempt,
        String repoUrl,
        String commit
) {}
