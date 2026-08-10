package disertatie.advisor.mavenplugin;

import disertatie.contracts.model.Component;
import org.apache.maven.project.MavenProject;

/*
 * O apariţie a unei componente în arborele de dependenţe al unui modul.
 *
 * directGroupId/directArtifactId/directVersion identifică dependinţa DIRECTĂ a
 * modulului care a adus (eventual tranzitiv) această componentă - folosite doar
 * ca context (raport / prompt LLM)
 */
public record Occurrence(
        Component component,
        MavenProject module,
        String directGroupId,
        String directArtifactId,
        String directVersion
) {}
