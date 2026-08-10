package disertatie.advisor.mavenplugin;

import disertatie.contracts.model.Component;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.project.MavenProject;
import org.apache.maven.shared.dependency.graph.DependencyNode;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

/*
 * BFS pe arborele rezolvat al unui modul din reactor: adâncime, marcaj direct/tranzitiv
 * şi calea de la modul (nu doar un bomRef) la componentă.
 */
public final class ReactorDependencyGraph {

    private ReactorDependencyGraph() {}

    public static List<Occurrence> compute(MavenProject module, DependencyNode root) {
        List<Occurrence> result = new ArrayList<>();

        Set<DependencyNode> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        Map<DependencyNode, DependencyNode> parent = new IdentityHashMap<>();
        Map<DependencyNode, Integer> depthByNode = new IdentityHashMap<>();
        Queue<DependencyNode> queue = new ArrayDeque<>();

        depthByNode.put(root, 0);
        visited.add(root);
        queue.add(root);

        while (!queue.isEmpty()) {
            DependencyNode current = queue.poll();
            int currentDepth = depthByNode.get(current);

            if (currentDepth > 0) {
                result.add(toOccurrence(module, current, currentDepth, parent, depthByNode));
            }

            List<DependencyNode> children = current.getChildren();
            if (children == null) continue;

            for (DependencyNode child : children) {
                if (visited.add(child)) {
                    depthByNode.put(child, currentDepth + 1);
                    parent.put(child, current);
                    queue.add(child);
                }
            }
        }

        return result;
    }

    private static Occurrence toOccurrence(MavenProject module, DependencyNode node, int depth,
                                            Map<DependencyNode, DependencyNode> parent,
                                            Map<DependencyNode, Integer> depthByNode) {
        Artifact artifact = node.getArtifact();
        String path = buildPath(module, node, parent);
        DependencyNode directAncestor = firstHopAncestor(node, parent, depthByNode);
        Artifact directArtifact = directAncestor.getArtifact();

        Component component = new Component(
                purl(artifact),
                nullToEmpty(artifact.getGroupId()),
                nullToEmpty(artifact.getArtifactId()),
                nullToEmpty(artifact.getVersion()),
                depth == 1,
                depth,
                path
        );

        return new Occurrence(component, module,
                directArtifact.getGroupId(), directArtifact.getArtifactId(), directArtifact.getVersion());
    }

    private static DependencyNode firstHopAncestor(DependencyNode node,
                                                     Map<DependencyNode, DependencyNode> parent,
                                                     Map<DependencyNode, Integer> depthByNode) {
        DependencyNode current = node;
        while (depthByNode.get(current) > 1) {
            current = parent.get(current);
        }
        return current;
    }

    private static String buildPath(MavenProject module, DependencyNode node,
                                     Map<DependencyNode, DependencyNode> parent) {
        Deque<String> segments = new ArrayDeque<>();
        DependencyNode current = node;
        while (current != null) {
            DependencyNode p = parent.get(current);
            if (p == null) {
                segments.addFirst(module.getArtifactId());
            } else {
                Artifact a = current.getArtifact();
                segments.addFirst(a.getArtifactId() + ":" + a.getVersion());
            }
            current = p;
        }
        return String.join(" > ", segments);
    }

    private static String purl(Artifact artifact) {
        return "pkg:maven/" + artifact.getGroupId() + "/" + artifact.getArtifactId()
                + "@" + artifact.getVersion();
    }

    private static String nullToEmpty(String s) {
        return s != null ? s : "";
    }
}
