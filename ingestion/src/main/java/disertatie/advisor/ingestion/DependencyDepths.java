package disertatie.advisor.ingestion;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Dependency;

import java.util.*;
import java.util.stream.Collectors;

/**
 * BFS pe graful de dependențe CycloneDX. Calculeaza adancimea minima,
 * marcajul direct/tranzitiv si calea de la radacina pentru fiecare componenta.
 * Logica pura — fara retea, baza sau broker.
 */
public final class DependencyDepths {

    private DependencyDepths() {}

    public record Result(int depth, boolean direct, String path) {}

    public static Map<String, Result> compute(Bom bom) {
        // Construieste graful de adiacenta: bomRef -> lista copii
        Map<String, List<String>> adj = new LinkedHashMap<>();
        if (bom.getDependencies() != null) {
            for (Dependency dep : bom.getDependencies()) {
                List<String> childDependencies = new ArrayList<>();
                if (dep.getDependencies() != null) {
                    for (Dependency childDependency : dep.getDependencies()) {
                        childDependencies.add(childDependency.getRef());
                    }
                }
                adj.put(dep.getRef(), childDependencies);
            }
        }

        // Gaseste radacina (componenta din metadata proiectului)
        String root = null;
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            root = bom.getMetadata().getComponent().getBomRef();
        }
        if (root == null || !adj.containsKey(root)) {
            // Fallback: primul nod fara parinti in graf
            Set<String> allValues = adj.values().stream()
                    .flatMap(List::stream)
                    .collect(Collectors.toSet());
            root = adj.keySet().stream()
                    .filter(r -> !allValues.contains(r))
                    .findFirst()
                    .orElse(null);
        }
        if (root == null) return Map.of();

        // BFS cu tratarea ciclurilor (visited set)
        Map<String, Result> results = new HashMap<>();
        Map<String, String> parent = new HashMap<>();
        Map<String, Integer> depth = new HashMap<>();
        Queue<String> queue = new ArrayDeque<>();

        depth.put(root, 0);
        queue.add(root);

        while (!queue.isEmpty()) {
            String curent = queue.poll();
            int adancimeCurenta = depth.get(curent);

            String path = buildPath(curent, parent);
            results.put(curent, new Result(adancimeCurenta, adancimeCurenta == 1, path));

            for (String child : adj.getOrDefault(curent, List.of())) {
                if (!depth.containsKey(child)) {
                    depth.put(child, adancimeCurenta + 1);
                    parent.put(child, curent);
                    queue.add(child);
                }
            }
        }

        return results;
    }

    private static String buildPath(String nod, Map<String, String> parent) {
        Deque<String> path = new ArrayDeque<>();
        String curent = nod;
        while (curent != null) {
            path.addFirst(curent);
            curent = parent.get(curent);
        }
        return String.join(" > ", path);
    }
}
