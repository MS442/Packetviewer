package com.example.packetviewer.is2.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * FIS input 2: "Pattern". Scores how ARTIFICIAL the digits of an address
 * look, from 0 (looks like an ordinary assigned address) to 100 (looks
 * hand-typed: 1.2.3.4, 111.111.111.111, dead:beef...).
 *
 * Hand-made fake addresses tend to be tidy, while genuinely assigned ones
 * are not. This is only a hint, though: famous real addresses such as
 * 8.8.8.8 or 1.1.1.1 also score high, which is exactly why the rule base
 * never lets Pattern alone push the verdict past QUESTIONABLE.
 *
 * Pure Java (no Android classes) so it can be unit-tested on the JVM.
 */
public final class PatternAnalyzer {

    private PatternAnalyzer() { }

    public static final class Result {
        public final double score;
        public final List<String> reasons;

        Result(double score, List<String> reasons) {
            this.score = score;
            this.reasons = reasons;
        }
    }

    /** Hex "words" that people like to type into made-up IPv6 addresses. */
    private static final int[] HEX_WORDS = {
            0xdead, 0xbeef, 0xcafe, 0xbabe, 0xface, 0xfeed, 0xf00d, 0xc0de, 0xd00d, 0xb00b, 0xfade
    };

    // ------------------------------------------------------------------
    // IPv4
    // ------------------------------------------------------------------

    public static Result analyzeV4(byte[] a) {
        int[] o = new int[4];
        for (int i = 0; i < 4; i++) o[i] = a[i] & 0xFF;

        double score = 0;
        List<String> why = new ArrayList<>();

        int equalPairs = 0;
        int seqSteps = 0;
        for (int i = 0; i < 3; i++) {
            if (o[i] == o[i + 1]) {
                equalPairs++;
            } else if (Math.abs(o[i + 1] - o[i]) == 1 && Math.min(o[i], o[i + 1]) >= 1) {
                // Steps through 0 are ignored: real networks are full of x.0.0.1 style addresses.
                seqSteps++;
            }
        }
        if (equalPairs > 0) {
            score += 20 * equalPairs;
            why.add(equalPairs + " repeated adjacent octet" + (equalPairs > 1 ? "s" : ""));
        }
        if (seqSteps > 0) {
            score += 20 * seqSteps;
            why.add(seqSteps + " consecutive-number step" + (seqSteps > 1 ? "s" : "") + " (like 1.2.3.4)");
        }
        if (o[0] == o[1] && o[1] == o[2] && o[2] == o[3]) {
            score += 25;
            why.add("all four octets are identical");
        }

        int repdigits = 0;
        for (int i = 0; i < 4; i++) {
            if (o[i] >= 11 && isRepdigit(o[i])) repdigits++;
        }
        if (repdigits > 0) {
            score += 10 * repdigits;
            why.add(repdigits + " octet" + (repdigits > 1 ? "s" : "") + " made of one repeated digit (11, 222...)");
        }

        int d = o[1] - o[0];
        if (d != 0 && o[2] - o[1] == d && o[3] - o[2] == d) {
            score += 40;
            why.add("evenly spaced octets (step " + d + ")");
        }

        int round = 0;
        for (int i = 1; i < 4; i++) {
            if (o[i] == 0 || o[i] == 255) round++;
        }
        if (round > 0) {
            score += 15 * round;
            why.add(round + " round octet" + (round > 1 ? "s" : "") + " (0 or 255) in the host part");
        }

        if (o[0] == o[2] && o[1] == o[3] && o[0] != o[1]) {
            score += 25;
            why.add("repeating pair a.b.a.b");
        }

        if (why.isEmpty()) why.add("no tidy digit patterns found");
        return new Result(Math.min(100, score), why);
    }

    // ------------------------------------------------------------------
    // IPv6
    // ------------------------------------------------------------------

    public static Result analyzeV6(byte[] a) {
        int[] g = new int[8];
        for (int i = 0; i < 8; i++) g[i] = ((a[2 * i] & 0xFF) << 8) | (a[2 * i + 1] & 0xFF);

        double score = 0;
        List<String> why = new ArrayList<>();

        // Adjacent identical non-zero groups (4700:4700)
        int equalPairs = 0;
        for (int i = 0; i < 7; i++) {
            if (g[i] != 0 && g[i] == g[i + 1]) equalPairs++;
        }
        if (equalPairs > 0) {
            score += 15 * equalPairs;
            why.add(equalPairs + " repeated adjacent group" + (equalPairs > 1 ? "s" : ""));
        }

        // Groups made of one repeated digit (1111, aaaa)
        int repdigits = 0;
        for (int i = 0; i < 8; i++) {
            if (g[i] != 0 && isRepeatedNibble(g[i])) repdigits++;
        }
        if (repdigits > 0) {
            score += 10 * repdigits;
            why.add(repdigits + " group" + (repdigits > 1 ? "s" : "") + " made of one repeated digit");
        }

        // Typed hex words
        List<String> words = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            for (int w : HEX_WORDS) {
                if (g[i] == w) words.add(String.format(Locale.US, "%04x", g[i]));
            }
        }
        if (!words.isEmpty()) {
            score += 25 * words.size();
            why.add("typed hex word" + (words.size() > 1 ? "s" : "") + ": " + join(words));
        }

        // Ascending / descending digit runs (1234:5678:9abc)
        int run = longestNibbleRun(g);
        if (run >= 4) {
            score += Math.min(70, (run - 3) * 14);
            why.add("a run of " + run + " consecutive digits (like 1234:5678)");
        }

        // First half repeated as second half
        boolean halvesEqual = true;
        boolean allZero = true;
        for (int i = 0; i < 4; i++) {
            if (g[i] != g[i + 4]) halvesEqual = false;
            if (g[i] != 0) allZero = false;
        }
        if (halvesEqual && !allZero) {
            score += 30;
            why.add("first half of the address repeated as the second half");
        }

        if (why.isEmpty()) why.add("no tidy digit patterns found");
        return new Result(Math.min(100, score), why);
    }

    /** True for numbers whose decimal digits are all the same, e.g. 11, 77, 222. */
    private static boolean isRepdigit(int n) {
        int last = n % 10;
        while (n > 0) {
            if (n % 10 != last) return false;
            n /= 10;
        }
        return true;
    }

    private static boolean isRepeatedNibble(int group) {
        int n = group & 0xF;
        return group == (n << 12 | n << 8 | n << 4 | n);
    }

    /** Longest run of nibbles that each step by +1 or each step by -1 (mod 16) across the 32 hex digits. */
    private static int longestNibbleRun(int[] g) {
        int[] n = new int[32];
        for (int i = 0; i < 8; i++) {
            n[4 * i] = (g[i] >> 12) & 0xF;
            n[4 * i + 1] = (g[i] >> 8) & 0xF;
            n[4 * i + 2] = (g[i] >> 4) & 0xF;
            n[4 * i + 3] = g[i] & 0xF;
        }
        int best = 1;
        int up = 1;
        int down = 1;
        for (int i = 1; i < 32; i++) {
            int diff = (n[i] - n[i - 1]) & 0xF;
            up = (diff == 1) ? up + 1 : 1;
            down = (diff == 15) ? down + 1 : 1;
            best = Math.max(best, Math.max(up, down));
        }
        return best;
    }

    private static String join(List<String> items) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(items.get(i));
        }
        return sb.toString();
    }
}
