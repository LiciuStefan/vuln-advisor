package disertatie.contracts.model;

import java.util.List;

public record Sbom(List<Component> components, String format, String raw) {}
