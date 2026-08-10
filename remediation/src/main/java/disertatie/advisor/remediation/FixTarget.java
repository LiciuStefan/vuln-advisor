package disertatie.advisor.remediation;

import java.nio.file.Path;

/*
 * Descrie exact ce trebuie modificat de bucla agentului: fişierul pom.xml ţintă
 * (poate fi alt modul decât rădăcina reactorului) şi strategia de scriere.
 * direct/path/versionBumpCategory sunt opţionale
 */
public record FixTarget(
        Path pomFile,
        WriteStrategy strategy,
        Boolean direct,
        String path,
        String versionBumpCategory
) {
    public static FixTarget direct(Path pomFile) {
        return new FixTarget(pomFile, WriteStrategy.DIRECT_VERSION, null, null, null);
    }
}
