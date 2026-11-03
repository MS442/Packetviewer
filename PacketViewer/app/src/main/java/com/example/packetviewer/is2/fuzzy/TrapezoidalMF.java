package com.example.packetviewer.is2.fuzzy;

/**
 * Trapezoidal membership function, defined by 4 points (a, b, c, d):
 *
 *        1 |       ______
 *          |      /      \
 *          |     /        \
 *        0 |____/__________\____
 *             a  b        c  d
 *
 * Degree rises linearly from 0 at 'a' to 1 at 'b', stays flat at 1
 * from 'b' to 'c' (the plateau), then falls linearly to 0 at 'd'.
 * Used for the "open-ended" sets at the extremes of a universe
 * (e.g. LOW starting at 0, or OLD extending to infinity).
 */
public class TrapezoidalMF implements MembershipFunction {

    private final double a, b, c, d;

    public TrapezoidalMF(double a, double b, double c, double d) {
        this.a = a;
        this.b = b;
        this.c = c;
        this.d = d;
    }

    @Override
    public double degreeOf(double x) {
        // Plateau first: for "shoulder" sets (a == b or c == d, e.g. FAR starting at 0
        // or SAME_SUBNET ending at 100) the edge value itself must count as full membership.
        if (x >= b && x <= c) return 1.0;
        if (x <= a || x >= d) return 0.0;
        if (x < b) return (x - a) / (b - a);
        return (d - x) / (d - c);
    }
}
