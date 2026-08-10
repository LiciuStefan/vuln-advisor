package disertatie.advisor.matching;

import disertatie.contracts.model.*;

import java.util.*;

public class MatchingService {

    private final OsvClient osvClient;
    private final EpssClient epssClient;
    private final KevCatalog kevCatalog;

    public MatchingService(OsvClient osvClient, EpssClient epssClient, KevCatalog kevCatalog) {
        this.osvClient = osvClient;
        this.epssClient = epssClient;
        this.kevCatalog = kevCatalog;
    }

    /*
     * Corelează componentele cu vulnerabilităţile OSV, îmbogăţeşte cu EPSS şi KEV.
     * Eşecul EPSS sau KEV nu e fatal — semnalul rămâne null/false.
     * Eşecul OSV e fatal şi propagă excepţia.
     */
    public List<MatchedVulnerability> match(List<Component> components) throws Exception {
        // Pas 1: interogare OSV → vulnerabilităţi cu CVSS calculat
        List<Vulnerability> vulnerabilities = osvClient.query(components);

        if (vulnerabilities.isEmpty()) return List.of();

        // Pas 2: scoruri EPSS pentru toate CVE-urile
        List<String> cveIds = vulnerabilities.stream()
                .map(Vulnerability::cveId)
                .filter(id -> id.startsWith("CVE-"))
                .distinct()
                .toList();

        Map<String, ExploitSignal> epssSignals;
        try {
            epssSignals = epssClient.fetchScores(cveIds);
        } catch (Exception e) {
            epssSignals = Map.of();
        }

        // Pas 3: corelăm fiecare vulnerabilitate cu componenta afectată şi semnalele
        Map<String, Component> componentByPurl = new HashMap<>();
        for (Component component : components) {
            componentByPurl.put(component.purl(), component);
        }

        List<MatchedVulnerability> result = new ArrayList<>();
        for (Vulnerability vuln : vulnerabilities) {
            Component component = componentByPurl.get(vuln.affectedPurl());
            if (component == null) {
                // Fallback: folosim primul component cu acelaşi artifact
                component = findByArtifact(components, vuln.affectedPurl());
            }
            if (component == null) continue;

            ExploitSignal signal = buildSignal(vuln.cveId(), epssSignals);
            result.add(new MatchedVulnerability(component, vuln, signal));
        }

        return result;
    }

    private ExploitSignal buildSignal(String cveId, Map<String, ExploitSignal> epssMap) {
        ExploitSignal epss = epssMap.get(cveId);
        boolean inKev = kevCatalog.isKnownExploited(cveId);
        String kevDate = inKev ? kevCatalog.dateAdded(cveId) : null;

        if (epss != null) {
            return new ExploitSignal(cveId, epss.epssScore(), epss.epssPercentile(), inKev, kevDate);
        }
        return new ExploitSignal(cveId, null, null, inKev, kevDate);
    }

    /*
     * Fallback pentru cazul în care affectedPurl nu are versiune (frecvent — OSV descrie
     * intervale afectate, nu o versiune anume, vezi OsvClient.resolveAffectedPurl):
     * potrivire EXACTĂ pe groupId+artifactId
     */
    Component findByArtifact(List<Component> components, String affectedPurl) {
        String[] groupAndArtifact = parseMavenGroupArtifact(affectedPurl);
        if (groupAndArtifact == null) return null;
        for (Component c : components) {
            if (c.group().equals(groupAndArtifact[0]) && c.artifact().equals(groupAndArtifact[1])) {
                return c;
            }
        }
        return null;
    }

    /* Extrage {groupId, artifactId} dintr-un purl "pkg:maven/<group>/<artifact>[@<version>]". */
    private String[] parseMavenGroupArtifact(String purl) {
        if (purl == null || !purl.startsWith("pkg:maven/")) return null;
        String rest = purl.substring("pkg:maven/".length());
        int at = rest.indexOf('@');
        if (at >= 0) rest = rest.substring(0, at);
        int slash = rest.indexOf('/');
        if (slash <= 0 || slash == rest.length() - 1) return null;
        return new String[]{ rest.substring(0, slash), rest.substring(slash + 1) };
    }
}
