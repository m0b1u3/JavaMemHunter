package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.BytecodeMaliceCheck;
import com.memhunter.agent.scoring.ScoringRule;

/**
 * Suppresses normal business components: a Servlet/Filter/Listener whose code comes from a
 * webapp's own jar/WEB-INF/classes and whose bytecode was read and shows no malicious features
 * is almost certainly legitimate application code, not a memshell. Returns a large negative score
 * to push it down to "low". Agent-type findings (bytecode-tampered etc.) are NEVER suppressed.
 *
 * <p>Suppression requires <em>positive</em> evidence of cleanliness: the bytecode must have been
 * read AND shown no malice. A component whose bytecode could not be read is left untouched (not
 * suppressed) — "unreadable" is not "clean". Code loaded from a temp directory is likewise never
 * treated as a normal webapp location even if the path ends in ".jar".
 */
public class BenignComponentRule implements ScoringRule {

    public String name() { return "benign-component"; }

    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.type == null || finding.className == null) return 0;
        if (finding.type.startsWith("agent-")) return 0;
        if (!isComponentFinding(finding.type)) return 0;

        if (!isNormalWebappCodeSource(finding.codeSource)) return 0;
        if (isHighEntropyName(finding.className)) return 0;

        // Require positive evidence of cleanliness: bytecode must have been read AND be malice-free.
        // "Unreadable bytecode" is NOT "clean bytecode" — never suppress on absence of evidence.
        if (!BytecodeMaliceCheck.hasReadableBytecode(finding.className, ctx)) return 0;
        if (BytecodeMaliceCheck.hasMalice(finding.className, ctx)) return 0;

        return -10;
    }

    private boolean isComponentFinding(String type) {
        return type.startsWith("tomcat-") || type.startsWith("spring-") || type.startsWith("class-");
    }

    private boolean isNormalWebappCodeSource(String cs) {
        if (cs == null || cs.isEmpty()) return false;
        // Exclude locations that are never a legitimate webapp component source, even if the
        // path superficially matches a webapp marker (e.g. a jar dropped in /tmp).
        if (cs.contains("/work/Catalina/")) return false;   // compiled JSP work dir
        if (cs.contains("/tmp/") || cs.contains("/var/tmp/")) return false;  // *nix temp-dropped payloads
        // Windows temp locations (target may run on a Windows JDK): match both slash styles.
        String lower = cs.toLowerCase();
        if (lower.contains("\\temp\\") || lower.contains("/temp/")
                || lower.contains("\\appdata\\local\\temp")) return false;
        return cs.contains("/WEB-INF/") || cs.contains(".jar")
            || cs.contains("/classes/") || cs.contains("/webapps/");
    }

    private boolean isHighEntropyName(String className) {
        String simple = className;
        int dot = className.lastIndexOf('.');
        if (dot >= 0) simple = className.substring(dot + 1);
        return simple.length() >= 6 && shannonEntropy(simple) > 3.5;
    }

    private double shannonEntropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        int[] freq = new int[128];
        int counted = 0;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch < 128) { freq[ch]++; counted++; }
        }
        if (counted == 0) return 0.0;
        double ent = 0.0;
        for (int f : freq) if (f > 0) {
            double p = (double) f / counted;
            ent -= p * (Math.log(p) / Math.log(2));
        }
        return ent;
    }
}
