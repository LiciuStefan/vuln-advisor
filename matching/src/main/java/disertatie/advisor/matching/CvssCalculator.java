package disertatie.advisor.matching;

import java.util.Map;

/*
 * Referinţă: https://www.first.org/cvss/v3.1/specification-document
 */
public final class CvssCalculator {

    private CvssCalculator() {}

    private static final Map<String, Double> ATTACK_VECTOR = Map.of("N", 0.85, "A", 0.62, "L", 0.55, "P", 0.2);
    private static final Map<String, Double> ATTACK_COMPLEXITY = Map.of("L", 0.77, "H", 0.44);
    private static final Map<String, Double> PRIVILEGES_REQUIRED = Map.of("N", 0.85, "L", 0.62, "H", 0.27);
    private static final Map<String, Double> MODIFIED_PRIVILEGES_REQUIRED = Map.of("N", 0.85, "L", 0.68, "H", 0.50);
    private static final Map<String, Double> USER_INTERACTION = Map.of("N", 0.85, "R", 0.62);
    private static final Map<String, Double> CONFIDENTIALITY_INTEGRITY_AVAILABILITY = Map.of("N", 0.00, "L", 0.22, "H", 0.56);

    /*
     * Parsează un vector CVSS v3.1 şi returnează scorul de bază (0.0–10.0).
     * Returnează 0.0 dacă vectorul e null, gol sau are format invalid.
     */
    public static double calculate(String vector) {
        if (vector == null || vector.isBlank()) return 0.0;
        try {
            return doCalculate(vector.trim());
        } catch (Exception e) {
            return 0.0;
        }
    }

    private static double doCalculate(String vector) {
        // Format: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        String[] parts = vector.startsWith("CVSS:") ? vector.split("/") : ("X/" + vector).split("/");
        Map<String, String> map = new java.util.HashMap<>();
        for (int i = 1; i < parts.length; i++) {
            String[] value = parts[i].split(":");
            if (value.length == 2) map.put(value[0], value[1]);
        }

        boolean scopeChanged = "C".equals(map.get("S"));
        double attackVector  = ATTACK_VECTOR.getOrDefault(map.get("AV"), 0.0);
        double attackComplexity  = ATTACK_COMPLEXITY.getOrDefault(map.get("AC"), 0.0);
        double privilegesRequired  = (scopeChanged ? MODIFIED_PRIVILEGES_REQUIRED : PRIVILEGES_REQUIRED).getOrDefault(map.get("PR"), 0.0);
        double userInteraction  = USER_INTERACTION.getOrDefault(map.get("UI"), 0.0);
        double confidentiality   = CONFIDENTIALITY_INTEGRITY_AVAILABILITY.getOrDefault(map.get("C"), 0.0);
        double integrity  = CONFIDENTIALITY_INTEGRITY_AVAILABILITY.getOrDefault(map.get("I"), 0.0);
        double availability   = CONFIDENTIALITY_INTEGRITY_AVAILABILITY.getOrDefault(map.get("A"), 0.0);

        double iss = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability);
        double impact;
        if (scopeChanged) {
            impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
        } else {
            impact = 6.42 * iss;
        }

        if (impact <= 0) return 0.0;

        double exploitability = 8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction;
        double base;
        if (scopeChanged) {
            base = Math.min(1.08 * (impact + exploitability), 10.0);
        } else {
            base = Math.min(impact + exploitability, 10.0);
        }

        return roundUp(base);
    }

    private static double roundUp(double value) {
        long rounded = (long) Math.ceil(value * 10);
        return rounded / 10.0;
    }
}
