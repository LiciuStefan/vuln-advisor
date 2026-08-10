package disertatie.advisor.prioritization;

import disertatie.contracts.model.Component;
import disertatie.contracts.model.ExploitSignal;
import disertatie.contracts.model.Reachability;
import disertatie.contracts.model.Vulnerability;

import java.util.LinkedHashMap;
import java.util.Map;

/*
 * Motorul de scoring
 *
 * Formula: scor = 100 · clamp(w_cvss·(cvss/10) + w_epss·epss
 *                              + w_reach·reach_factor + w_depth·depth_factor, 0, 1)
 *                          · kev_multiplier
 */
public final class ScoringEngine {

    private ScoringEngine() {}

    public static ScoreOutput score(Component component,
                                    Vulnerability vulnerability,
                                    ExploitSignal signal,
                                    Reachability reachability,
                                    WeightConfig weights) {
        double cvssNorm   = vulnerability.cvss() / 10.0;
        double epss       = epssValue(signal);
        double reachFactor = reachFactor(reachability);
        double depthFactor = depthFactor(component);
        double kevMult    = kevMultiplier(signal, weights);

        double raw = weights.wCvss() * cvssNorm
                   + weights.wEpss() * epss
                   + weights.wReach() * reachFactor
                   + weights.wDepth() * depthFactor;

        double clamped = Math.max(0.0, Math.min(1.0, raw));
        double finalScore = 100.0 * clamped * kevMult;

        Map<String, Double> breakdown = new LinkedHashMap<>();
        breakdown.put(WeightConfig.W_CVSS,  weights.wCvss() * cvssNorm);
        breakdown.put(WeightConfig.W_EPSS,  weights.wEpss() * epss);
        breakdown.put(WeightConfig.W_REACH, weights.wReach() * reachFactor);
        breakdown.put(WeightConfig.W_DEPTH, weights.wDepth() * depthFactor);
        breakdown.put(WeightConfig.KEV_MULTIPLIER, kevMult);

        Map<String, Double> usedWeights = new LinkedHashMap<>();
        usedWeights.put(WeightConfig.W_CVSS,         weights.wCvss());
        usedWeights.put(WeightConfig.W_EPSS,         weights.wEpss());
        usedWeights.put(WeightConfig.W_REACH,        weights.wReach());
        usedWeights.put(WeightConfig.W_DEPTH,        weights.wDepth());
        usedWeights.put(WeightConfig.KEV_MULTIPLIER, weights.kevMultiplier());

        return new ScoreOutput(finalScore, breakdown, usedWeights);
    }

    private static double epssValue(ExploitSignal signal) {
        if (signal == null || signal.epssScore() == null) return 0.0;
        return signal.epssScore();
    }

    private static double reachFactor(Reachability r) {
        if (r == null) return 0.5;
        return switch (r) {
            case REACHED       -> 1.0;
            case UNDETERMINED  -> 0.5;
            case NOT_REACHED   -> 0.1;
        };
    }

    private static double depthFactor(Component c) {
        if (c.direct()) return 1.0;
        return Math.max(0.1, Math.min(1.0, 1.0 / (1.0 + c.depth())));
    }

    private static double kevMultiplier(ExploitSignal signal, WeightConfig weights) {
        if (signal != null && signal.inKev()) return weights.kevMultiplier();
        return 1.0;
    }
}
