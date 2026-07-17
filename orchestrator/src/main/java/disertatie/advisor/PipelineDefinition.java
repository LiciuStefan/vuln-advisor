package disertatie.advisor;

import disertatie.contracts.model.Queues;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Component
public class PipelineDefinition {

    private static final List<String> ORDER = List.of("ingestion", "matching", "reachability");

    private static final Map<String, String> QUEUE_BY_STAGE = Map.of(
            "ingestion", Queues.STAGE_INGESTION,
            "matching", Queues.STAGE_MATCHING,
            "reachability", Queues.STAGE_REACHABILITY
    );

    public String firstStage() {
        return ORDER.get(0);
    }

    public Optional<String> nextStage(String current) {
        int index = ORDER.indexOf(current);
        if (index < 0 || index + 1 >= ORDER.size()) {
            return Optional.empty();
        }
        return Optional.of(ORDER.get(index + 1));
    }

    public String queueFor(String stage) {
        String queue = QUEUE_BY_STAGE.get(stage);
        if (queue == null) {
            throw new IllegalArgumentException("Etapă necunoscută: " + stage);
        }
        return queue;
    }

}
