package com.example.packetviewer.is2.fuzzy;

/**
 * A named linguistic term (e.g. "HIGH", "MEDIUM", "CRITICAL") paired
 * with the membership function that defines its shape over a
 * variable's universe of discourse.
 */
public class FuzzySet {

    private final String name;
    private final MembershipFunction membershipFunction;

    public FuzzySet(String name, MembershipFunction membershipFunction) {
        this.name = name;
        this.membershipFunction = membershipFunction;
    }

    public String getName() {
        return name;
    }

    public double degreeOf(double x) {
        return membershipFunction.degreeOf(x);
    }
}
