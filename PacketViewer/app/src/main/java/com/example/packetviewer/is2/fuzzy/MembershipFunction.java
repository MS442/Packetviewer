package com.example.packetviewer.is2.fuzzy;

/**
 * Core abstraction of Fuzzy Set Theory (Zadeh, 1965): a membership
 * function maps a crisp input value to a "degree of truth" in the
 * range [0.0, 1.0], instead of the binary {0, 1} of classical (crisp)
 * set membership.
 *
 * e.g. degreeOf(72.0) for a "HIGH similarity" set might return 0.6,
 * meaning the value 72 is "somewhat, but not completely, HIGH".
 */
public interface MembershipFunction {
    double degreeOf(double x);
}
