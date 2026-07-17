package disertatie.advisor;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import disertatie.contracts.model.Queues;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitConfig {

    @Bean
    public Queue jobsQueue() {
        return QueueBuilder.durable(Queues.JOBS).build();
    }

    @Bean
    public Queue stageIngestionQueue() {
        return QueueBuilder.durable(Queues.STAGE_INGESTION).build();
    }

    @Bean
    public Queue stageReachabilityQueue() {
        return QueueBuilder.durable(Queues.STAGE_REACHABILITY).build();
    }

    @Bean
    public Queue stageMatchingQueue() {
        return QueueBuilder.durable(Queues.STAGE_MATCHING).build();
    }

    @Bean
    public Queue stageResultsQueue() {
        return QueueBuilder.durable(Queues.STAGE_RESULTS).build();
    }

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper()
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }

    @SuppressWarnings("deprecation")
    @Bean
    public MessageConverter jsonMessageConverter(ObjectMapper objectMapper) {
        Jackson2JsonMessageConverter converter = new Jackson2JsonMessageConverter(objectMapper);
        converter.setAlwaysConvertToInferredType(true);
        return converter;
    }
}
