package com.example.packetviewer.is2.analysis;

import com.example.packetviewer.cn.utils.TransitionUtils;
import com.example.packetviewer.is2.analysis.RangeClassifier.Scenario;
import com.example.packetviewer.is2.fuzzy.FakeIpFIS;
import com.example.packetviewer.is2.fuzzy.InferenceResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The whole IS2 pipeline for one address:
 *
 *   address text (+ optional prefix, hex packet, scenario)
 *      -> SubnetStep        -> subnet + host position (STEP 0, before the duplicate check)
 *      -> RangeClassifier   -> Range   (0-100)
 *      -> PatternAnalyzer   -> Pattern (0-100)
 *      -> HeaderForensics   -> Header  (0-100)
 *      -> FakeIpFIS (Mamdani) -> Suspicion score (0-100) + verdict
 *
 * Pure Java (no Android classes) so it can be unit-tested on the JVM.
 */
public final class FakeIpAnalyzer {

    /** Everything the UI needs: the three crisp inputs with their evidence, and the FIS output. */
    public static final class Analysis {
        public final String input;
        public final String canonical;
        public final String protocol;
        public final Scenario scenario;
        public final RangeClassifier.Result range;
        public final PatternAnalyzer.Result pattern;
        public final HeaderForensics.Result header;
        public final Map<String, Map<String, Double>> fuzzified;
        public final InferenceResult inference;
        /** Defuzzified Suspicion score, 0-100. */
        public final double score;
        /** Output set name, e.g. LIKELY_FAKE. */
        public final String label;
        /** Display text, e.g. "LIKELY FAKE". */
        public final String verdict;
        /** STEP 0 result; null when the subnet step was skipped. */
        public final SubnetStep.Result subnet;

        Analysis(String input, String canonical, String protocol, Scenario scenario,
                 RangeClassifier.Result range, PatternAnalyzer.Result pattern, HeaderForensics.Result header,
                 Map<String, Map<String, Double>> fuzzified, InferenceResult inference,
                 SubnetStep.Result subnet) {
            this.subnet = subnet;
            this.input = input;
            this.canonical = canonical;
            this.protocol = protocol;
            this.scenario = scenario;
            this.range = range;
            this.pattern = pattern;
            this.header = header;
            this.fuzzified = fuzzified;
            this.inference = inference;
            this.score = inference.crispOutput;
            this.label = inference.dominantLabel;
            this.verdict = inference.dominantLabel.replace('_', ' ');
        }
    }

    private final FakeIpFIS fis = new FakeIpFIS();

    /** Analysis without the subnet step (kept for tests and for callers that have no prefix). */
    public Analysis analyze(String ip, String hex, Scenario scenario) {
        return analyze(ip, hex, scenario, null);
    }

    /**
     * @param ip         IPv4 or IPv6 text (compressed IPv6 and dotted tails accepted); may carry
     *                   a prefix as "192.168.1.5/26"
     * @param hex        optional raw packet header bytes as hex, may be null or empty
     * @param scenario   where the address is expected to be seen
     * @param prefixText null = skip subnetting; "" = auto (/24 for IPv4, /64 for IPv6);
     *                   otherwise "26", "/26" or a dotted IPv4 mask
     * @return the analysis, or null when {@code ip} is not a valid address; an invalid prefix
     *         throws IllegalArgumentException with a readable message
     */
    public Analysis analyze(String ip, String hex, Scenario scenario, String prefixText) {
        if (ip == null) return null;
        String text = ip.trim();
        int slash = text.indexOf('/');
        if (slash >= 0) {
            if (prefixText == null || prefixText.trim().isEmpty()) prefixText = text.substring(slash + 1);
            text = text.substring(0, slash).trim();
        }

        byte[] v4 = null;
        byte[] v6 = null;
        if (text.contains(":")) v6 = TransitionUtils.parseIPv6(text);
        else v4 = TransitionUtils.parseIPv4(text);
        if (v4 == null && v6 == null) return null;

        boolean isV6 = v6 != null;
        byte[] addr = isV6 ? v6 : v4;

        // STEP 0: subnetting
        SubnetStep.Result sub = null;
        if (prefixText != null) {
            sub = SubnetStep.run(addr, prefixText);
            if (sub.error != null) throw new IllegalArgumentException(sub.error);
        }

        RangeClassifier.Result range = isV6
                ? RangeClassifier.classifyV6(addr, scenario)
                : RangeClassifier.classifyV4(addr, scenario);
        double floor = SubnetStep.minRange(sub);
        if (floor > range.score) {
            range = new RangeClassifier.Result(range.kind, floor,
                    "address " + SubnetStep.rangeNote(sub) + "; block: " + range.reason);
        }
        PatternAnalyzer.Result pattern = isV6 ? PatternAnalyzer.analyzeV6(addr) : PatternAnalyzer.analyzeV4(addr);
        HeaderForensics.Result header = HeaderForensics.analyze(hex, addr, isV6);

        InferenceResult inference = fis.evaluate(range.score, pattern.score, header.score);
        Map<String, Map<String, Double>> fuzz = fis.fuzzify(range.score, pattern.score, header.score);

        String canonical = isV6 ? TransitionUtils.formatIPv6Full(addr) : TransitionUtils.formatIPv4(addr);
        return new Analysis(text, canonical, isV6 ? "IPv6" : "IPv4", scenario, range, pattern, header, fuzz, inference, sub);
    }

    /** The single stored form of an address (IPv4 dotted, IPv6 fully expanded), or null if invalid. */
    public static String canonicalForm(String ip) {
        if (ip == null) return null;
        String text = ip.trim();
        if (text.contains(":")) {
            byte[] v6 = TransitionUtils.parseIPv6(text);
            return v6 == null ? null : TransitionUtils.formatIPv6Full(v6);
        }
        byte[] v4 = TransitionUtils.parseIPv4(text);
        return v4 == null ? null : TransitionUtils.formatIPv4(v4);
    }

    public int ruleCount() {
        return fis.getRuleCount();
    }

    // ------------------------------------------------------------------
    // REPORT (monospace text shown in the Detector tab)
    // ------------------------------------------------------------------

    public static String report(Analysis a) {
        StringBuilder sb = new StringBuilder();

        if (a.subnet != null) sb.append(SubnetStep.report(a.subnet));
        sb.append("=== RESULT ===\n");
        sb.append("Address   : ").append(a.canonical).append(" (").append(a.protocol).append(")\n");
        sb.append("Scenario  : ").append(a.scenario == Scenario.LAN ? "Local network (LAN)" : "Public Internet source").append('\n');
        sb.append(String.format(Locale.US, "Suspicion : %.1f / 100%n", a.score));
        sb.append("Verdict   : ").append(a.verdict).append("\n\n");

        sb.append("=== EVIDENCE (crisp inputs to the FIS) ===\n");
        sb.append(String.format(Locale.US, "1) Range   = %3.0f  %s%n", a.range.score, a.range.reason));
        sb.append(String.format(Locale.US, "2) Pattern = %3.0f  %s%n", a.pattern.score, join(a.pattern.reasons)));
        sb.append(String.format(Locale.US, "3) Header  = %3.0f  %s%n", a.header.score, join(a.header.reasons)));
        sb.append('\n');

        sb.append("=== STEP 1 - FUZZIFICATION ===\n");
        sb.append("Each crisp input gets a degree of membership (0-1) in every set:\n");
        double[] crisp = {a.range.score, a.pattern.score, a.header.score};
        int i = 0;
        for (Map.Entry<String, Map<String, Double>> variable : a.fuzzified.entrySet()) {
            sb.append(String.format(Locale.US, "%-8s(%3.0f):", variable.getKey(), crisp[i++]));
            for (Map.Entry<String, Double> set : variable.getValue().entrySet()) {
                sb.append(String.format(Locale.US, "  %s %.2f", set.getKey(), set.getValue()));
            }
            sb.append('\n');
        }
        sb.append('\n');

        sb.append("=== STEP 2 - RULE EVALUATION (AND = min) ===\n");
        List<InferenceResult.FiredRule> fired = new ArrayList<>(a.inference.firedRules);
        Collections.sort(fired, new Comparator<InferenceResult.FiredRule>() {
            @Override
            public int compare(InferenceResult.FiredRule x, InferenceResult.FiredRule y) {
                return Double.compare(y.strength, x.strength);
            }
        });
        sb.append(fired.size()).append(" of the 27 rules fired. Strongest:\n");
        for (int r = 0; r < fired.size() && r < 6; r++) {
            sb.append(String.format(Locale.US, "  %.2f  %s%n", fired.get(r).strength, fired.get(r).description));
        }
        sb.append('\n');

        sb.append("=== STEPS 3 + 4 - AGGREGATION + DEFUZZIFICATION ===\n");
        sb.append("Every fired rule clips its output set at its strength; the clipped\n");
        sb.append("shapes are merged with max. The centroid (centre of gravity) of the\n");
        sb.append(String.format(Locale.US, "merged shape is %.1f, closest to %s.%n%n", a.score, a.verdict));

        sb.append("=== NOTE ===\n");
        sb.append("Offline heuristic score from the address block (RFC 6890), its digit\n");
        sb.append("pattern and the optional header bytes. It cannot prove spoofing or tell\n");
        sb.append("whether an address is actually assigned or in use.");
        return sb.toString();
    }

    private static String join(List<String> items) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append("; ");
            sb.append(items.get(i));
        }
        return sb.toString();
    }
}
