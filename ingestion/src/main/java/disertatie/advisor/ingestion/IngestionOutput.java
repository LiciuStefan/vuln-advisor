package disertatie.advisor.ingestion;

import disertatie.contracts.model.BuildSystem;
import disertatie.contracts.model.Component;

import java.nio.file.Path;
import java.util.List;

record IngestionOutput(BuildSystem buildSystem, List<Component> components, Path projectDir) {}
