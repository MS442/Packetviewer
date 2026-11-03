package com.example.packetviewer.is2.fuzzy;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A single Mamdani IF-THEN rule, e.g.:
 *
 *   IF Similarity IS HIGH AND Proximity IS SAME_SUBNET AND Recency IS RECENT
 *   THEN Risk IS CRITICAL
 *
 * All antecedents are combined with fuzzy AND (= min of their degrees),
 * matching classical Mamdani inference. The rule's firing strength is
 * then used to clip the consequent output set during aggregation.
 */
public class FuzzyRule {

    /** One "Variable IS Set" clause in the rule's antecedent (IF part). */
    public static class Antecedent {
        public final String variableName;
        public final String setName;

        public Antecedent(String variableName, String setName) {
            this.variableName = variableName;
            this.setName = setName;
        }
    }

    private final List<Antecedent> antecedents;
    private final String outputSetName; // consequent (THEN part) - a set on the output variable
    private final String description;   // human-readable label - shown in the "explain reasoning" trace

    private FuzzyRule(List<Antecedent> antecedents, String outputSetName, String description) {
        this.antecedents = antecedents;
        this.outputSetName = outputSetName;
        this.description = description;
    }

    public String getOutputSetName() {
        return outputSetName;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Fuzzy AND across all antecedents = the MINIMUM of their individual
     * membership degrees (classical Mamdani t-norm). This is the rule's
     * "firing strength" - how strongly this rule applies given the
     * current fuzzified inputs.
     */
    public double firingStrength(Map<String, Map<String, Double>> fuzzifiedInputs) {
        double strength = 1.0;
        for (Antecedent a : antecedents) {
            Map<String, Double> degrees = fuzzifiedInputs.get(a.variableName);
            double degree = (degrees != null && degrees.containsKey(a.setName)) ? degrees.get(a.setName) : 0.0;
            strength = Math.min(strength, degree);
        }
        return strength;
    }

    // ------------------------------------------------------------------
    // Fluent builder: FuzzyRule.builder().when("Similarity","HIGH")
    //                            .and("Proximity","SAME_SUBNET")
    //                            .then("CRITICAL", "High similarity + same subnet");
    // ------------------------------------------------------------------

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final List<Antecedent> antecedents = new ArrayList<>();

        public Builder when(String variableName, String setName) {
            antecedents.add(new Antecedent(variableName, setName));
            return this;
        }

        public Builder and(String variableName, String setName) {
            antecedents.add(new Antecedent(variableName, setName));
            return this;
        }

        public FuzzyRule then(String outputSetName, String description) {
            return new FuzzyRule(new ArrayList<>(antecedents), outputSetName, description);
        }
    }
}
