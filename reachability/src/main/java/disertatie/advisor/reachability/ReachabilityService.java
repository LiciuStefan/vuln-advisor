package disertatie.advisor.reachability;

import disertatie.contracts.model.Reachability;

import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/*
 * Calculează reachability pentru UN modul: primeşte classpath-ul deja rezolvat
 * (appClassesDir + depJars) şi, pentru fiecare purl vulnerabil din acel modul,
 * mulţimea de clase ale componentei vulnerabile — ambele rezolvate de apelant
 * (ex. FixMojo, prin API-uri Maven native: DependencyNode, RepositorySystem).
 * Rezolvarea de artefacte e specifică sistemului de build folosit, nu ţine de
 * reachability, deci rămâne la apelant — acest serviciu ştie doar despre
 * "classpath-ul unui modul" şi "clasele unei componente", nu despre Maven.
 *
 * Orchestrarea pe mai multe module ale unui reactor (agregarea rezultatelor per
 * purl când acelaşi artefact apare, cu verdicte diferite, în module diferite)
 */
public class ReachabilityService {

    private final CallGraphBuilder callGraphBuilder;

    public ReachabilityService(CallGraphBuilder callGraphBuilder) {
        this.callGraphBuilder = callGraphBuilder;
    }

    public Map<String, Reachability> reachabilityForModule(Path appClassesDir, List<Path> depJars,
            Map<String, Set<String>> vulnerableClassesByPurl) throws Exception {

        Set<String> reachableClasses = callGraphBuilder.reachableClasses(appClassesDir, depJars);

        Map<String, Reachability> result = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : vulnerableClassesByPurl.entrySet()) {
            Set<String> vulnClasses = entry.getValue();
            Reachability status = vulnClasses.isEmpty()
                    ? Reachability.UNDETERMINED
                    : (Collections.disjoint(reachableClasses, vulnClasses)
                            ? Reachability.NOT_REACHED : Reachability.REACHED);
            result.put(entry.getKey(), status);
        }
        return result;
    }

    /* Agregare pe mai multe module: REACHED dacă apare oriunde, altfel UNDETERMINED dacă apare oriunde, altfel NOT_REACHED. */
    public static Reachability combine(Reachability a, Reachability b) {
        if (a == Reachability.REACHED || b == Reachability.REACHED) return Reachability.REACHED;
        if (a == Reachability.UNDETERMINED || b == Reachability.UNDETERMINED) return Reachability.UNDETERMINED;
        return Reachability.NOT_REACHED;
    }
}
