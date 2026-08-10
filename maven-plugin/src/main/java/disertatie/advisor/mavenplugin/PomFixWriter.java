package disertatie.advisor.mavenplugin;

import disertatie.advisor.remediation.WriteStrategy;
import disertatie.advisor.remediation.VersionEditability;
import disertatie.contracts.model.Component;

import java.nio.file.Path;

/*
 Calculează fixul exact (fişier ţintă, strategie, coordonate) pentru o vulnerabilitate
 dintr-un modul al reactorului
 */
public final class PomFixWriter {

    private PomFixWriter() {}

    public record Fix(Path pomFile, WriteStrategy strategy,
                       String groupId, String artifactId, String newVersion) {}

    public static Fix resolveFix(Occurrence occurrence, String fixedVersion,
            VersionEditability editability) {
        Component component = occurrence.component();
        Path pomFile = occurrence.module().getFile().toPath();
        WriteStrategy strategy = switch (editability) {
            case INLINE, PROPERTY -> WriteStrategy.DIRECT_VERSION;
            case MANAGED_LOCALLY -> WriteStrategy.DEPENDENCY_MANAGEMENT_EDIT;
            case INHERITED, NOT_DECLARED -> WriteStrategy.DEPENDENCY_MANAGEMENT_ADD;
        };
        return new Fix(pomFile, strategy, component.group(), component.artifact(), fixedVersion);
    }

    public static String snippet(Fix fix) {
        String dependencyBlock = "    <dependency>\n"
                + "      <groupId>" + fix.groupId() + "</groupId>\n"
                + "      <artifactId>" + fix.artifactId() + "</artifactId>\n"
                + "      <version>" + fix.newVersion() + "</version>\n"
                + "    </dependency>";

        if (fix.strategy() == WriteStrategy.DIRECT_VERSION) {
            return dependencyBlock.stripLeading();
        }

        return "<dependencyManagement>\n  <dependencies>\n" + dependencyBlock
                + "\n  </dependencies>\n</dependencyManagement>";
    }
}
