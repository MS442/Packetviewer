package com.example.packetviewer.is2.fuzzy;

import java.util.List;

/**
 * The full output of running the Mamdani engine once: the defuzzified
 * crisp score, its dominant linguistic label, and a trace of every
 * rule that fired (with what strength) - useful both for debugging
 * and as an "explainable AI" viva talking point.
 */
public class InferenceResult {

    public final double crispOutput;
    public final String dominantLabel;
    public final List<FiredRule> firedRules;

    public InferenceResult(double crispOutput, String dominantLabel, List<FiredRule> firedRules) {
        this.crispOutput = crispOutput;
        this.dominantLabel = dominantLabel;
        this.firedRules = firedRules;
    }

    public static class FiredRule {
        public final String description;
        public final double strength;

        public FiredRule(String description, double strength) {
            this.description = description;
            this.strength = strength;
        }

        @Override
        public String toString() {
            return String.format("%s (fired %.0f%%)", description, strength * 100);
        }
    }
}
