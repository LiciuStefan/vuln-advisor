package disertatie.advisor.app;

import disertatie.contracts.model.Queues;
import disertatie.contracts.port.AnalysisJob;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/analyses")
@Tag(name = "Analyses", description = "Pornire și monitorizare analize de vulnerabilități")
public class AnalysisController {

    private final RabbitTemplate rabbitTemplate;

    public AnalysisController(RabbitTemplate rabbitTemplate) {
        this.rabbitTemplate = rabbitTemplate;
    }

    @PostMapping
    public ResponseEntity<AnalysisResponse> startAnalysis(@RequestBody @Valid AnalysisRequest request) {
        UUID analysisRunId = UUID.randomUUID();
        rabbitTemplate.convertAndSend(
                Queues.JOBS,
                new AnalysisJob(analysisRunId, request.repoUrl(), request.commit())
        );
        return ResponseEntity.accepted().body(new AnalysisResponse(analysisRunId, "QUEUED"));
    }
}
