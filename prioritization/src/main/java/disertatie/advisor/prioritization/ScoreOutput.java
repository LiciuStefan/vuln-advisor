package disertatie.advisor.prioritization;

import java.util.Map;

/*
 * scor + explicabilitate completă.
 * weightsUsed - ponderile utilizate
 */
public record ScoreOutput(
        double score,
        Map<String, Double> factorBreakdown,
        Map<String, Double> weightsUsed
) {}
