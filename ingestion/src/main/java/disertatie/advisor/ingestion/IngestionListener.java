package disertatie.advisor.ingestion;

import tools.jackson.databind.json.JsonMapper;
import disertatie.contracts.model.Component;
import disertatie.contracts.model.Queues;
import disertatie.contracts.model.RepositoryRef;
import disertatie.contracts.port.StageResult;
import disertatie.contracts.port.StageTask;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

@Service
public class IngestionListener {

    private final IngestionService ingestionService;
    private final JdbcClient db;
    private final RabbitTemplate rabbitTemplate;
    private final JsonMapper jsonMapper;

    @Value("${workspace.dir:/workspace}")
    private String workspaceDir;

    public IngestionListener(IngestionService ingestionService,
                             JdbcClient db,
                             RabbitTemplate rabbitTemplate,
                             JsonMapper jsonMapper) {
        this.ingestionService = ingestionService;
        this.db = db;
        this.rabbitTemplate = rabbitTemplate;
        this.jsonMapper = jsonMapper;
    }

    @RabbitListener(queues = Queues.STAGE_INGESTION)
    public void onTask(StageTask task) {
        long start = System.currentTimeMillis();
        try {
            IngestionOutput output = ingestionService.ingest(
                    new RepositoryRef(task.repoUrl(), task.commit()),
                    task.analysisRunId()
            );

            writeComponentsToDB(task.analysisRunId(), output.components());
            writeToWorkspace(task.analysisRunId(), output.components());

            publishResult(task, "COMPLETED", System.currentTimeMillis() - start, null);
        } catch (Exception e) {
            publishResult(task, "FAILED", System.currentTimeMillis() - start, e.getMessage());
        }
    }

    private void writeComponentsToDB(String analysisRunId, List<Component> components) {
        UUID runId = UUID.fromString(analysisRunId);
        for (Component c : components) {
            db.sql("""
                    INSERT INTO component
                        (analysis_run_id, purl, group_id, artifact_id, version, direct, depth, path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """)
              .params(runId, c.purl(), c.group(), c.artifact(), c.version(),
                      c.direct(), c.depth(), c.path())
              .update();
        }
    }

    private void writeToWorkspace(String analysisRunId, List<Component> components) throws Exception {
        Path dir = Path.of(workspaceDir, analysisRunId);
        Files.createDirectories(dir);
        jsonMapper.writeValue(dir.resolve("components.json").toFile(), components);
    }

    private void publishResult(StageTask task, String status, long durationMs, String error) {
        rabbitTemplate.convertAndSend(
                Queues.STAGE_RESULTS,
                new StageResult(task.analysisRunId(), task.stage(), status, durationMs, error)
        );
    }
}
