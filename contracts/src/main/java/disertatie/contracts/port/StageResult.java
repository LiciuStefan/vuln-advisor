package disertatie.contracts.port;

import java.util.UUID;

/**
 * Publicat de orice worker după terminarea etapei. status ∈ {COMPLETED, FAILED}.
 */
public record StageResult(
        UUID analysisRunId,
        String stage,
        Status status,
        long durationMs,
        String error
) {}
