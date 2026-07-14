package disertatie.advisor.ingestion;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

@Component
public class SbomGenerator {

    private static final String CYCLONEDX_GOAL =
            "org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom";

    public Path generate(Path projectDir) throws Exception {
        Path logFile = projectDir.resolve("sbom-generation.log");

        ProcessBuilder processBuilder = new ProcessBuilder(
                "mvn",
                CYCLONEDX_GOAL,
                "-Dcyclonedx.outputFormat=json",
                "--batch-mode"
        );
        processBuilder.directory(projectDir.toFile());
        processBuilder.redirectOutput(logFile.toFile());
        processBuilder.redirectError(ProcessBuilder.Redirect.appendTo(logFile.toFile()));

        Process process = processBuilder.start();
        boolean finished = process.waitFor(10, TimeUnit.MINUTES);

        if (!finished) {
            process.destroyForcibly();
            throw new RuntimeException("SBOM generation expired after 10 minutes");
        }

        if (process.exitValue() != 0) {
            String log = Files.exists(logFile) ? Files.readString(logFile) : "";
            throw new RuntimeException("SBOM generation failed ( " + process.exitValue() + "): " + log);
        }

        Path bomFile = projectDir.resolve("target/bom.json");
        if (!Files.exists(bomFile)) {
            throw new IOException("bom.json was not found after SBOM generation: " + bomFile);
        }
        return bomFile;
    }
}
