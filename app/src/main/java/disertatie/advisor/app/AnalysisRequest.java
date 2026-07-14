package disertatie.advisor.app;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Cerere de pornire a unei analize")
public record AnalysisRequest(
        @NotBlank
        @Schema(description = "URL-ul repository-ului Git de analizat",
                example = "https://github.com/spring-projects/spring-petclinic")
        String repoUrl,

        @Schema(description = "Commit SHA de analizat (opțional — implicit HEAD)",
                example = "a1b2c3d4")
        String commit
) {}
