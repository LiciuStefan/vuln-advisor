package disertatie.advisor.mavenplugin;

import org.apache.maven.artifact.versioning.DefaultArtifactVersion;

/*
 * Clasifică un fix drept major bump sau minor/patch, folosind DefaultArtifactVersion
 * din maven-artifact (deja pe classpath-ul oricărui plugin Maven).
 */
public final class VersionBumpClassifier {

    private VersionBumpClassifier() {}

    public enum Category { MAJOR, MINOR_OR_PATCH, UNKNOWN }

    public static Category classify(String currentVersion, String fixedVersion) {
        if (currentVersion == null || currentVersion.isBlank()
                || fixedVersion == null || fixedVersion.isBlank()) {
            return Category.UNKNOWN;
        }
        Integer currentMajor = majorOf(currentVersion);
        Integer fixedMajor = majorOf(fixedVersion);
        if (currentMajor == null || fixedMajor == null) return Category.UNKNOWN;
        return !currentMajor.equals(fixedMajor) ? Category.MAJOR : Category.MINOR_OR_PATCH;
    }

    public static int compare(String a, String b) {
        int[] ta = numericTuple(a);
        int[] tb = numericTuple(b);
        int len = Math.max(ta.length, tb.length);
        for (int i = 0; i < len; i++) {
            int va = i < ta.length ? ta[i] : 0;
            int vb = i < tb.length ? tb[i] : 0;
            if (va != vb) return Integer.compare(va, vb);
        }
        return 0;
    }

    private static Integer majorOf(String version) {
        DefaultArtifactVersion parsed = new DefaultArtifactVersion(version);
        boolean degenerate = parsed.getMajorVersion() == 0 && parsed.getMinorVersion() == 0
                && parsed.getIncrementalVersion() == 0
                && version.equals(parsed.getQualifier());
        if (!degenerate) return parsed.getMajorVersion();

        int[] tuple = numericTuple(version);
        return tuple.length > 0 ? tuple[0] : null;
    }

    private static int[] numericTuple(String version) {
        String[] parts = version.split("[.\\-]");
        int count = 0;
        int[] nums = new int[parts.length];
        for (String part : parts) {
            try {
                nums[count] = Integer.parseInt(part);
                count++;
            } catch (NumberFormatException e) {
                break;
            }
        }
        int[] result = new int[count];
        System.arraycopy(nums, 0, result, 0, count);
        return result;
    }
}
