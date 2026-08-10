package disertatie.advisor.reachability;

import sootup.callgraph.CallGraph;
import sootup.callgraph.ClassHierarchyAnalysisAlgorithm;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.model.SourceType;
import sootup.core.signatures.MethodSignature;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.JrtFileSystemAnalysisInputLocation;
import sootup.java.core.views.JavaView;

import java.nio.file.Path;
import java.util.*;

/*
 * Construieşte call graph-ul static (CHA) al aplicaţiei analizate
 * şi returnează mulţimea FQN-urilor claselor atinse din punctele de intrare
 */
public class CallGraphBuilder {

    public Set<String> reachableClasses(Path appClassesDir, List<Path> depJars) throws Exception {
        List<AnalysisInputLocation> inputLocations = new ArrayList<>();
        inputLocations.add(new JavaClassPathAnalysisInputLocation(
                appClassesDir.toString(), SourceType.Application));
        for (Path jar : depJars) {
            inputLocations.add(new JavaClassPathAnalysisInputLocation(
                    jar.toString(), SourceType.Library));
        }
        // JDK-ul rulează SootUp nu are acces la clasele runtime (java.lang.*, java.util.*
        // etc.) fără această locaţie explicită, fără ea, orice apel către o clasă JDK
        // nu poate fi rezolvat, iar CHA se opreşte la prima graniţă JDK din graf.
        inputLocations.add(new JrtFileSystemAnalysisInputLocation(SourceType.Library));

        JavaView view = new JavaView(inputLocations);

        ClassHierarchyAnalysisAlgorithm cha = new ClassHierarchyAnalysisAlgorithm(view);

        // Alegem punctele de intrare, explicit, în loc să ne bazăm pe auto-detecţia
        // internă a lui SootUp (cha.initialize() fara argumente - găseşte main() dacă e
        // exact unul, altfel throw, şi foloseam excepţia ca declanşator pentru fallback-ul
        // de mai jos)
        List<MethodSignature> entryPoints = findMainMethods(view);
        if (entryPoints.size() != 1) {
            // 0 metode main() sau
            // >1 (mai multe module cu main() ajunse pe acelaşi classpath agregat) - în
            // ambele cazuri nu putem alege automat UN singur punct de intrare fără
            // ambiguitate, aşa că tratăm toată suprafaţa publică a claselor proprii
            // modulului ca potenţial apelabilă
            entryPoints = findPublicApiMethods(view);
        }

        if (entryPoints.isEmpty()) {
            throw new IllegalStateException(
                    "No valid entrypoint found in: " + appClassesDir);
        }

        CallGraph callGraph = cha.initialize(entryPoints);

        return collectReachableClasses(callGraph, callGraph.getEntryMethods());
    }

    private List<MethodSignature> findMainMethods(JavaView view) {
        List<MethodSignature> mains = new ArrayList<>();
        view.getClasses().forEach(javaSootClass ->
                javaSootClass.getMethods().forEach(method -> {
                    if ("main".equals(method.getName()) && method.isStatic() && method.isPublic()) {
                        mains.add(method.getSignature());
                    }
                })
        );
        return mains;
    }

    private List<MethodSignature> findPublicApiMethods(JavaView view) {
        List<MethodSignature> entryPoints = new ArrayList<>();
        view.getClasses()
                .filter(javaSootClass -> javaSootClass.isApplicationClass())
                .forEach(javaSootClass ->
                        javaSootClass.getMethods().forEach(method -> {
                            if (method.isPublic() && method.hasBody()) {
                                entryPoints.add(method.getSignature());
                            }
                        })
                );
        return entryPoints;
    }

    private Set<String> collectReachableClasses(CallGraph callGraph, List<MethodSignature> entryPoints) {
        // CHA calculează tranzitiv toate metodele atinse din entry points.
        // getMethodSignatures() returnează exact această mulţime.
        Set<String> reachableClasses = new HashSet<>();
        for (MethodSignature signature : callGraph.getMethodSignatures()) {
            reachableClasses.add(signature.getDeclClassType().getFullyQualifiedName());
        }
        return reachableClasses;
    }
}
