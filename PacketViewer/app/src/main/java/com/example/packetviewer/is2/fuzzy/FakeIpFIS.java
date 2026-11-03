package com.example.packetviewer.is2.fuzzy;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Mamdani Fuzzy Inference System that scores how likely an IP address is
 * to be FAKE (made up, spoofed, or not a valid host address).
 *
 * It only WIRES UP the generic MamdaniEngine (fuzzification -> rule
 * evaluation -> aggregation -> centroid defuzzification) with this
 * application's variables and rule base; it holds no inference logic.
 *
 * INPUTS (all crisp values on a 0-100 scale, produced by is2.analysis):
 *   1. Range   - how reserved / non-routable the address block is
 *                (ROUTABLE, LIMITED, RESERVED)
 *   2. Pattern - how artificial / hand-typed the digits look
 *                (NATURAL, PATTERNED, ARTIFICIAL)
 *   3. Header  - how inconsistent the optional raw packet header is
 *                (CONSISTENT, SUSPECT, FORGED)
 *
 * OUTPUT:
 *   Suspicion [0-100] - GENUINE, QUESTIONABLE, SUSPICIOUS, LIKELY_FAKE
 *
 * RULE BASE: the full 3 x 3 x 3 = 27 combinations, so every possible input
 * triggers at least one rule (see OUTCOME below, which is the rule table).
 */
public class FakeIpFIS {

    public static final String VAR_RANGE = "Range";
    public static final String VAR_PATTERN = "Pattern";
    public static final String VAR_HEADER = "Header";
    public static final String VAR_SUSPICION = "Suspicion";

    // Input set names
    public static final String ROUTABLE = "ROUTABLE";
    public static final String LIMITED = "LIMITED";
    public static final String RESERVED = "RESERVED";

    public static final String NATURAL = "NATURAL";
    public static final String PATTERNED = "PATTERNED";
    public static final String ARTIFICIAL = "ARTIFICIAL";

    public static final String CONSISTENT = "CONSISTENT";
    public static final String SUSPECT = "SUSPECT";
    public static final String FORGED = "FORGED";

    // Output set names
    public static final String GENUINE = "GENUINE";
    public static final String QUESTIONABLE = "QUESTIONABLE";
    public static final String SUSPICIOUS = "SUSPICIOUS";
    public static final String LIKELY_FAKE = "LIKELY_FAKE";

    private static final String[] RANGE_SETS = {ROUTABLE, LIMITED, RESERVED};
    private static final String[] PATTERN_SETS = {NATURAL, PATTERNED, ARTIFICIAL};
    private static final String[] HEADER_SETS = {CONSISTENT, SUSPECT, FORGED};

    /**
     * THE RULE TABLE. OUTCOME[range][pattern][header] is the output set.
     *
     * Reading guide:
     *  - A bad header is the strongest single signal (forged headers are the
     *    textbook symptom of spoofing), so SUSPECT -> SUSPICIOUS and
     *    FORGED -> LIKELY_FAKE almost everywhere.
     *  - A reserved range alone is SUSPICIOUS, because such an address can
     *    never be a normal public host; combined with another red flag it
     *    becomes LIKELY_FAKE.
     *  - A weird-looking pattern alone is never worse than QUESTIONABLE, as
     *    real addresses such as 1.1.1.1 or 8.8.8.8 look "typed" too.
     */
    private static final String[][][] OUTCOME = {
            // ----- Range = ROUTABLE -----
            {
                    /* NATURAL    */ {GENUINE, SUSPICIOUS, LIKELY_FAKE},
                    /* PATTERNED  */ {GENUINE, SUSPICIOUS, LIKELY_FAKE},
                    /* ARTIFICIAL */ {QUESTIONABLE, SUSPICIOUS, LIKELY_FAKE}
            },
            // ----- Range = LIMITED (private seen on the Internet, CGNAT, 6to4...) -----
            {
                    /* NATURAL    */ {QUESTIONABLE, SUSPICIOUS, LIKELY_FAKE},
                    /* PATTERNED  */ {QUESTIONABLE, SUSPICIOUS, LIKELY_FAKE},
                    /* ARTIFICIAL */ {SUSPICIOUS, LIKELY_FAKE, LIKELY_FAKE}
            },
            // ----- Range = RESERVED (loopback, multicast, documentation, Class E...) -----
            {
                    /* NATURAL    */ {SUSPICIOUS, LIKELY_FAKE, LIKELY_FAKE},
                    /* PATTERNED  */ {SUSPICIOUS, LIKELY_FAKE, LIKELY_FAKE},
                    /* ARTIFICIAL */ {LIKELY_FAKE, LIKELY_FAKE, LIKELY_FAKE}
            }
    };

    private final FuzzyVariable range;
    private final FuzzyVariable pattern;
    private final FuzzyVariable header;
    private final FuzzyVariable suspicion;
    private final MamdaniEngine engine;
    private int ruleCount = 0;

    public FakeIpFIS() {
        // ---------------- INPUT 1: Range (0 = ordinary public block, 100 = never valid) ----------------
        range = new FuzzyVariable(VAR_RANGE, 0, 100)
                .addSet(new FuzzySet(ROUTABLE, new TrapezoidalMF(0, 0, 10, 35)))
                .addSet(new FuzzySet(LIMITED, new TriangularMF(20, 45, 70)))
                .addSet(new FuzzySet(RESERVED, new TrapezoidalMF(55, 80, 100, 100)));

        // ---------------- INPUT 2: Pattern (0 = looks random, 100 = obviously typed) ----------------
        pattern = new FuzzyVariable(VAR_PATTERN, 0, 100)
                .addSet(new FuzzySet(NATURAL, new TrapezoidalMF(0, 0, 15, 40)))
                .addSet(new FuzzySet(PATTERNED, new TriangularMF(25, 50, 75)))
                .addSet(new FuzzySet(ARTIFICIAL, new TrapezoidalMF(60, 80, 100, 100)));

        // ---------------- INPUT 3: Header (0 = consistent / not supplied, 100 = forged) ----------------
        header = new FuzzyVariable(VAR_HEADER, 0, 100)
                .addSet(new FuzzySet(CONSISTENT, new TrapezoidalMF(0, 0, 10, 30)))
                .addSet(new FuzzySet(SUSPECT, new TriangularMF(15, 40, 65)))
                .addSet(new FuzzySet(FORGED, new TrapezoidalMF(50, 75, 100, 100)));

        // ---------------- OUTPUT: Suspicion score (0-100) ----------------
        suspicion = new FuzzyVariable(VAR_SUSPICION, 0, 100)
                .addSet(new FuzzySet(GENUINE, new TrapezoidalMF(0, 0, 15, 35)))
                .addSet(new FuzzySet(QUESTIONABLE, new TriangularMF(20, 40, 60)))
                .addSet(new FuzzySet(SUSPICIOUS, new TriangularMF(45, 65, 85)))
                .addSet(new FuzzySet(LIKELY_FAKE, new TrapezoidalMF(70, 88, 100, 100)));

        engine = new MamdaniEngine(suspicion, 200); // 200-step discretisation for the centroid
        engine.addInputVariable(range);
        engine.addInputVariable(pattern);
        engine.addInputVariable(header);

        buildRuleBase();
    }

    private void buildRuleBase() {
        for (int r = 0; r < RANGE_SETS.length; r++) {
            for (int p = 0; p < PATTERN_SETS.length; p++) {
                for (int h = 0; h < HEADER_SETS.length; h++) {
                    String out = OUTCOME[r][p][h];
                    String text = "IF Range IS " + RANGE_SETS[r]
                            + " AND Pattern IS " + PATTERN_SETS[p]
                            + " AND Header IS " + HEADER_SETS[h]
                            + " THEN Suspicion IS " + out;
                    engine.addRule(FuzzyRule.builder()
                            .when(VAR_RANGE, RANGE_SETS[r])
                            .and(VAR_PATTERN, PATTERN_SETS[p])
                            .and(VAR_HEADER, HEADER_SETS[h])
                            .then(out, text));
                    ruleCount++;
                }
            }
        }
    }

    /** Runs the full Mamdani pipeline for one address. All inputs are on a 0-100 scale. */
    public InferenceResult evaluate(double rangeScore, double patternScore, double headerScore) {
        Map<String, Double> inputs = new LinkedHashMap<>();
        inputs.put(VAR_RANGE, clamp(rangeScore));
        inputs.put(VAR_PATTERN, clamp(patternScore));
        inputs.put(VAR_HEADER, clamp(headerScore));
        return engine.infer(inputs);
    }

    /** Stage 1 of the pipeline on its own, for the step-by-step report: degree of every set of every input. */
    public Map<String, Map<String, Double>> fuzzify(double rangeScore, double patternScore, double headerScore) {
        Map<String, Map<String, Double>> out = new LinkedHashMap<>();
        out.put(VAR_RANGE, range.fuzzify(clamp(rangeScore)));
        out.put(VAR_PATTERN, pattern.fuzzify(clamp(patternScore)));
        out.put(VAR_HEADER, header.fuzzify(clamp(headerScore)));
        return out;
    }

    public int getRuleCount() {
        return ruleCount;
    }

    private static double clamp(double v) {
        return Math.max(0.0, Math.min(100.0, v));
    }
}
