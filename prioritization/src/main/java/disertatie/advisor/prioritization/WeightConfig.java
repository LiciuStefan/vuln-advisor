package disertatie.advisor.prioritization;

public record WeightConfig(
        double wCvss,
        double wEpss,
        double wReach,
        double wDepth,
        double kevMultiplier,
        double actionThreshold
) {
    public static final String W_CVSS         = "cvss";
    public static final String W_EPSS         = "epss";
    public static final String W_REACH        = "reach";
    public static final String W_DEPTH        = "depth";
    public static final String KEV_MULTIPLIER = "kevMultiplier";

    public static WeightConfig defaults() {
        return new WeightConfig(0.30, 0.30, 0.25, 0.15, 1.5, 50.0);
    }

    /* Copie cu acelaşi ponderi, doar cu pragul de acţiune înlocuit (ex. parametru CLI/Mojo). */
    public WeightConfig withActionThreshold(double newActionThreshold) {
        return new WeightConfig(wCvss, wEpss, wReach, wDepth, kevMultiplier, newActionThreshold);
    }
}
