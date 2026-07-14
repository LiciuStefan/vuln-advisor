package disertatie.advisor.ingestion;

import disertatie.contracts.model.RepositoryRef;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.CloneCommand;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;

@Component
public class RepositoryCloner {

    @Value("${workspace.dir:/workspace}")
    private String workspaceDir;

    /**
     * Cloneaza repo-ul in /workspace/<analysisRunId>/repo.
     * Daca un commit e specificat, face checkout pe el (clone complet).
     * Altfel, clone superficial (depth=1) pentru viteza.
     */
    public Path clone(RepositoryRef ref, String analysisRunId) throws Exception {
        Path targetDir = Path.of(workspaceDir, analysisRunId, "repo");
        Files.createDirectories(targetDir);

        boolean specifiedCommit = ref.commit() != null && !ref.commit().isBlank();

        CloneCommand cmd = Git.cloneRepository()
                .setURI(ref.url())
                .setDirectory(targetDir.toFile());

        if (!specifiedCommit) {
            cmd.setDepth(1);
        }

        try (Git git = cmd.call()) {
            if (specifiedCommit) {
                git.checkout()
                   .setName(ref.commit())
                   .call();
            }
        }

        return targetDir;
    }
}
