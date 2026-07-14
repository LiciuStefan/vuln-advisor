package disertatie.advisor.app;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Răspuns la pornirea unei analize")
public record AnalysisResponse(
        @Schema(description = "ID-ul unic al analizei", example = "550e8400-e29b-41d4-a716-446655440000")
        String analysisRunId,

        @Schema(description = "Starea inițială", example = "QUEUED")
        String status
) {}
