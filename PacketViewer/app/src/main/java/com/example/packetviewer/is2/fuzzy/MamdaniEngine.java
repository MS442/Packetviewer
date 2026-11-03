package com.example.packetviewer.is2.fuzzy;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Generic Mamdani-style Fuzzy Inference Engine.
 *
 * Pipeline (the 4 classical FIS stages):
 *
 *   1. FUZZIFICATION  - each crisp input is converted into degrees of
 *                        membership across all of its variable's sets
 *                        (FuzzyVariable.fuzzify()).
 *
 *   2. RULE EVALUATION - every rule's antecedents are combined with
 *                        fuzzy AND (= min) to get a firing strength
 *                        (FuzzyRule.firingStrength()).
 *
 *   3. AGGREGATION     - each fired rule "clips" its consequent output
 *                        set's membership function at its firing
 *                        strength (Mamdani min-implication), then all
 *                        clipped sets are combined point-wise with MAX
 *                        across the output universe.
 *
 *   4. DEFUZZIFICATION - the aggregated fuzzy output surface is
 *                        collapsed back into a single crisp number
 *                        using the Centroid (Center of Gravity) method:
 *
 *                             sum( x * membership(x) )
 *                        z* = -------------------------   over the
 *                             sum( membership(x) )          universe
 *
 * This engine is intentionally generic (not tied to IP duplicate
 * checking) so it can be reused for any Mamdani FIS with any number
 * of input variables.
 */
public class MamdaniEngine {

    private final List<FuzzyVariable> inputVariables = new ArrayList<>();
    private final FuzzyVariable outputVariable;
    private final List<FuzzyRule> rules = new ArrayList<>();

    /** Resolution of the discretized output universe used for centroid integration. */
    private final int resolution;

    public MamdaniEngine(FuzzyVariable outputVariable, int resolution) {
        this.outputVariable = outputVariable;
        this.resolution = resolution;
    }

    public MamdaniEngine addInputVariable(FuzzyVariable variable) {
        inputVariables.add(variable);
        return this;
    }

    public MamdaniEngine addRule(FuzzyRule rule) {
        rules.add(rule);
        return this;
    }

    /**
     * Runs the full 4-stage Mamdani pipeline for one set of crisp
     * inputs, keyed by input variable name.
     */
    public InferenceResult infer(Map<String, Double> crispInputs) {

        // ---------- STAGE 1: FUZZIFICATION ----------
        Map<String, Map<String, Double>> fuzzifiedInputs = new LinkedHashMap<>();
        for (FuzzyVariable variable : inputVariables) {
            Double crispValue = crispInputs.get(variable.getName());
            if (crispValue == null) {
                throw new IllegalArgumentException("Missing crisp input for variable '" + variable.getName() + "'");
            }
            fuzzifiedInputs.put(variable.getName(), variable.fuzzify(crispValue));
        }

        // ---------- STAGE 2: RULE EVALUATION ----------
        List<InferenceResult.FiredRule> fired = new ArrayList<>();
        // Track the STRONGEST firing strength assigned to each output set name
        // (if two rules both conclude "HIGH", we keep the max strength, per Mamdani aggregation).
        Map<String, Double> strengthPerOutputSet = new LinkedHashMap<>();

        for (FuzzyRule rule : rules) {
            double strength = rule.firingStrength(fuzzifiedInputs);
            if (strength > 0.0) {
                fired.add(new InferenceResult.FiredRule(rule.getDescription(), strength));
                String outSet = rule.getOutputSetName();
                double existing = strengthPerOutputSet.containsKey(outSet) ? strengthPerOutputSet.get(outSet) : 0.0;
                strengthPerOutputSet.put(outSet, Math.max(existing, strength));
            }
        }

        // ---------- STAGE 3: AGGREGATION (clip-then-max across the output universe) ----------
        double min = outputVariable.getUniverseMin();
        double max = outputVariable.getUniverseMax();
        double step = (max - min) / resolution;

        double[] aggregatedMembership = new double[resolution + 1];
        double[] xValues = new double[resolution + 1];

        for (int i = 0; i <= resolution; i++) {
            double x = min + i * step;
            xValues[i] = x;

            double pointMax = 0.0;
            for (Map.Entry<String, Double> entry : strengthPerOutputSet.entrySet()) {
                FuzzySet outSet = outputVariable.getSet(entry.getKey());
                double clippedDegree = Math.min(outSet.degreeOf(x), entry.getValue()); // Mamdani min-implication
                pointMax = Math.max(pointMax, clippedDegree);                          // aggregation via max
            }
            aggregatedMembership[i] = pointMax;
        }

        // ---------- STAGE 4: DEFUZZIFICATION (Centroid / Center of Gravity) ----------
        double numerator = 0.0;
        double denominator = 0.0;
        for (int i = 0; i <= resolution; i++) {
            numerator += xValues[i] * aggregatedMembership[i];
            denominator += aggregatedMembership[i];
        }

        double crispOutput = (denominator == 0.0) ? min : (numerator / denominator);

        // Determine the dominant linguistic label at the crisp output point
        String dominantLabel = "UNDEFINED";
        double bestDegree = -1.0;
        for (FuzzySet set : outputVariable.getSets().values()) {
            double degree = set.degreeOf(crispOutput);
            if (degree > bestDegree) {
                bestDegree = degree;
                dominantLabel = set.getName();
            }
        }

        return new InferenceResult(crispOutput, dominantLabel, fired);
    }
}
