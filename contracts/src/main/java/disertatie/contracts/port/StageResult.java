package disertatie.contracts.port;

/**
 * Publicat de orice worker după terminarea etapei. status ∈ {COMPLETED, FAILED}.
 */
public record StageResult(
        String analysisRunId,
        String stage,
        String status,
        long durationMs,
        String error
) {}
