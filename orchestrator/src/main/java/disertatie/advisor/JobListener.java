package disertatie.advisor;

import disertatie.contracts.port.AnalysisJob;
import disertatie.contracts.port.StageResult;
import disertatie.contracts.port.StageTask;
import disertatie.contracts.port.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

@Component
public class JobListener {

    private static final Logger log = LoggerFactory.getLogger(JobListener.class);

    private final JdbcClient db;
    private final RabbitTemplate rabbit;
    private final PipelineDefinition pipeline;

    public JobListener(JdbcClient db, RabbitTemplate rabbit, PipelineDefinition pipeline) {
        this.db = db;
        this.rabbit = rabbit;
        this.pipeline = pipeline;
    }

    @RabbitListener(queues = disertatie.contracts.model.Queues.JOBS)
    public void onJob(AnalysisJob job) {
        log.info("Job started for {} ({})", job.repoUrl(), job.analysisRunId());

        db.sql("""
                INSERT INTO analysis_run (id, repo_url, commit_sha, status, started_at)
                VALUES (?, ?, ?, 'RUNNING', now())
                """)
                .params(job.analysisRunId(), job.repoUrl(), job.commit())
                .update();

        String first = pipeline.firstStage();
        recordStageStart(job.analysisRunId(), first);
        rabbit.convertAndSend(pipeline.queueFor(first),
                StageTask.firstForRepo(job.analysisRunId(), first, job.repoUrl(), job.commit()));
        log.info("Etapa '{}' pornită pentru {}", first, job.analysisRunId());
    }

    private void recordStageStart(UUID analysisRunId, String stage) {
        db.sql("""
                INSERT INTO stage_execution (run_id, stage_name, status, started_at, attempt)
                VALUES (?, ?, 'RUNNING', now(), 1)
                """)
                .params(analysisRunId, stage)
                .update();
    }

    @RabbitListener(queues = disertatie.contracts.model.Queues.STAGE_RESULTS)
    public void onResult(StageResult result) {
        log.info("Rezultat '{}' = {} pentru {}",
                result.stage(), result.status(), result.analysisRunId());

        updateStageExecution(result);

        if (result.status() == Status.FAILED) {
            markRun(result, "FAILED");
            log.warn("Analiza {} a eșuat la etapa '{}': {}",
                    result.analysisRunId(), result.stage(), result.error());
            return;
        }

        Optional<String> next = pipeline.nextStage(result.stage());

        if (next.isPresent()) {
            String nextStage = next.get();
            UUID id = result.analysisRunId();
            recordStageStart(id, nextStage);
            rabbit.convertAndSend(pipeline.queueFor(nextStage),
                    StageTask.first(id, nextStage));
            log.info("Etapa '{}' pornită pentru {}", nextStage, id);
        } else {
            markRun(result, "COMPLETED");
            log.info("Analiza {} s-a încheiat", result.analysisRunId());
        }

    }

    private void updateStageExecution(StageResult result) {
        db.sql("""
                UPDATE stage_execution
                SET status = ?, duration_ms = ?, error = ?
                WHERE run_id = ? AND stage_name = ?
                """)
                .params(result.status().name(), result.durationMs(), result.error(),
                        result.analysisRunId(), result.stage())
                .update();
    }

    private void markRun(StageResult result, String status) {
        db.sql("UPDATE analysis_run SET status = ?, completed_at = now() WHERE id = ?")
                .params(status, result.analysisRunId())
                .update();
    }
}
