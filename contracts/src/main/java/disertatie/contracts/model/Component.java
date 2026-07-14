package disertatie.contracts.model;

public record Component(
        String purl,
        String group,
        String artifact,
        String version,
        boolean direct,
        int depth,
        String path
) {}
