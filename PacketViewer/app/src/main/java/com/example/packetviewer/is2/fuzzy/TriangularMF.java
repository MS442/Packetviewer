package com.example.packetviewer.is2.fuzzy;

/**
 * Triangular membership function, defined by 3 points (a, b, c):
 *
 *        1 |        /\
 *          |       /  \
 *          |      /    \
 *        0 |_____/______\_____
 *              a   b      c
 *
 * Degree rises linearly from 0 at 'a' to 1 at 'b' (the peak),
 * then falls linearly back to 0 at 'c'.
 */
public class TriangularMF implements MembershipFunction {

    private final double a, b, c;

    public TriangularMF(double a, double b, double c) {
        this.a = a;
        this.b = b;
        this.c = c;
    }

    @Override
    public double degreeOf(double x) {
        if (x <= a || x >= c) return 0.0;
        if (x == b) return 1.0;
        if (x < b) return (x - a) / (b - a);
        return (c - x) / (c - b);
    }
}
