package com.example.packetviewer.is2.fuzzy;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A linguistic variable (e.g. "Similarity", "Risk") - a named
 * dimension with a bounded universe of discourse [min, max] and a
 * collection of overlapping FuzzySets ("LOW", "MEDIUM", "HIGH", ...)
 * that partition that universe.
 */
public class FuzzyVariable {

    private final String name;
    private final double universeMin;
    private final double universeMax;
    private final Map<String, FuzzySet> sets = new LinkedHashMap<>();

    public FuzzyVariable(String name, double universeMin, double universeMax) {
        this.name = name;
        this.universeMin = universeMin;
        this.universeMax = universeMax;
    }

    public FuzzyVariable addSet(FuzzySet set) {
        sets.put(set.getName(), set);
        return this;
    }

    public String getName() {
        return name;
    }

    public double getUniverseMin() {
        return universeMin;
    }

    public double getUniverseMax() {
        return universeMax;
    }

    public Map<String, FuzzySet> getSets() {
        return sets;
    }

    public FuzzySet getSet(String setName) {
        FuzzySet s = sets.get(setName);
        if (s == null) {
            throw new IllegalArgumentException("Unknown fuzzy set '" + setName + "' on variable '" + name + "'");
        }
        return s;
    }

    /**
     * FUZZIFICATION: converts one crisp input value into its degree
     * of membership in EVERY set of this variable simultaneously.
     * e.g. a similarity of 55% might be {LOW: 0.0, MEDIUM: 0.83, HIGH: 0.0}.
     */
    public Map<String, Double> fuzzify(double crispValue) {
        Map<String, Double> degrees = new LinkedHashMap<>();
        for (FuzzySet set : sets.values()) {
            degrees.put(set.getName(), set.degreeOf(crispValue));
        }
        return degrees;
    }
}
