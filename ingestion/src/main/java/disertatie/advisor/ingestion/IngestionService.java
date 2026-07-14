package disertatie.advisor.ingestion;

import disertatie.contracts.model.BuildSystem;
import disertatie.contracts.model.Component;
import disertatie.contracts.model.RepositoryRef;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.List;

@Service
public class IngestionService {

    private final RepositoryCloner cloner;
    private final SbomGenerator sbomGenerator;
    private final SbomParser sbomParser;

    public IngestionService(RepositoryCloner cloner, SbomGenerator sbomGenerator, SbomParser sbomParser) {
        this.cloner = cloner;
        this.sbomGenerator = sbomGenerator;
        this.sbomParser = sbomParser;
    }

    /**
     * Pas 1: cloneaza repo → Pas 2: genereaza SBOM → Pas 3: parseaza componente.
     * Returneaza lista de componente cu adancimea si marcajul direct/tranzitiv.
     */
    public IngestionOutput ingest(RepositoryRef ref, String analysisRunId) throws Exception {
        Path proiectDir = cloner.clone(ref, analysisRunId);
        Path bomFile = sbomGenerator.generate(proiectDir);
        List<Component> components = sbomParser.parse(bomFile);
        return new IngestionOutput(BuildSystem.MAVEN, components, proiectDir);
    }
}
