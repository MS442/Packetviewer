package com.example.packetviewer.cn.net;

import com.example.packetviewer.cn.utils.TransitionUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Dual-stack behaviour computed from the user's numbers:
 *  - RFC 6724 destination address selection (precedence table, longest prefix match)
 *  - RFC 8305 Happy Eyeballs v2 connection racing (250 ms connection attempt delay)
 */
public final class DualStack {

    public static final double CONNECTION_ATTEMPT_DELAY_MS = 250.0;   // RFC 8305 section 5

    /** One candidate destination with the (user supplied) path properties. */
    public static final class Candidate {
        public final byte[] addr;          // 4 or 16 bytes
        public final double rttMs;
        public final boolean works;        // false = packets are black-holed
        public int precedence;
        public Candidate(byte[] addr, double rttMs, boolean works) {
            this.addr = addr; this.rttMs = rttMs; this.works = works;
        }
        public boolean isV6() { return addr.length == 16; }
        public String text() { return isV6() ? TransitionUtils.formatIPv6(addr) : TransitionUtils.formatIPv4(addr); }
    }

    public static final class Outcome {
        public final List<Candidate> order = new ArrayList<>();
        public final List<String> timeline = new ArrayList<>();
        public Candidate winner;            // null if everything failed
        public double connectMs;
    }

    // RFC 6724 section 2.1 default policy table: {prefix, length, precedence}
    private static final String[][] TABLE = {
            {"::1", "128", "50"}, {"::", "0", "40"}, {"::ffff:0:0", "96", "35"},
            {"2002::", "16", "30"}, {"2001::", "32", "5"}, {"fc00::", "7", "3"},
            {"::", "96", "1"}, {"fec0::", "10", "1"}, {"3ffe::", "16", "1"}};

    public static int precedence(byte[] addr) {
        byte[] a = addr;
        if (addr.length == 4) {                       // IPv4 is looked up as ::ffff:a.b.c.d
            a = new byte[16];
            a[10] = (byte) 0xFF; a[11] = (byte) 0xFF;
            System.arraycopy(addr, 0, a, 12, 4);
        }
        int best = -1, bestLen = -1;
        for (String[] row : TABLE) {
            byte[] pfx = TransitionUtils.parseIPv6(row[0]);
            int len = Integer.parseInt(row[1]);
            if (matches(a, pfx, len) && len > bestLen) { bestLen = len; best = Integer.parseInt(row[2]); }
        }
        return best;
    }

    private static boolean matches(byte[] a, byte[] p, int bits) {
        for (int i = 0; i < bits; i++) {
            int m = 0x80 >> (i % 8);
            if ((a[i / 8] & m) != (p[i / 8] & m)) return false;
        }
        return true;
    }

    /** Sorts by RFC 6724 rule 6 (higher precedence first); stable so DNS order breaks ties (rule 10). */
    public static void sort(List<Candidate> list) {
        for (Candidate c : list) c.precedence = precedence(c.addr);
        List<Candidate> copy = new ArrayList<>(list);
        java.util.Collections.sort(copy, (x, y) -> Integer.compare(y.precedence, x.precedence));
        list.clear();
        list.addAll(copy);
    }

    /**
     * Races the sorted candidates: start the first at t=0, start the next after
     * 250 ms or as soon as the previous one fails, take the first that connects.
     * A working path connects after one RTT; a black-holed path never answers.
     */
    public static Outcome race(List<Candidate> candidates) {
        Outcome o = new Outcome();
        List<Candidate> list = new ArrayList<>(candidates);
        sort(list);
        o.order.addAll(list);
        double start = 0;
        double best = Double.POSITIVE_INFINITY;
        for (int i = 0; i < list.size(); i++) {
            Candidate c = list.get(i);
            o.timeline.add(String.format(java.util.Locale.US, "t=%6.1f ms  start %s attempt to %s",
                    start, c.isV6() ? "IPv6" : "IPv4", c.text()));
            if (c.works) {
                double done = start + c.rttMs;
                o.timeline.add(String.format(java.util.Locale.US, "t=%6.1f ms  %s SYN/ACK received", done, c.isV6() ? "IPv6" : "IPv4"));
                if (done < best) { best = done; o.winner = c; }
            } else {
                o.timeline.add("             " + (c.isV6() ? "IPv6" : "IPv4") + " attempt gets no answer (black-holed)");
            }
            // next attempt begins after the delay, but never later than the current winner is known
            double next = start + CONNECTION_ATTEMPT_DELAY_MS;
            if (best <= next) break;                       // somebody already won before the next start
            start = next;
        }
        if (o.winner != null) {
            o.connectMs = best;
            o.timeline.add(String.format(java.util.Locale.US, "t=%6.1f ms  winner: %s %s, other attempts cancelled",
                    best, o.winner.isV6() ? "IPv6" : "IPv4", o.winner.text()));
        } else {
            o.connectMs = Double.NaN;
            o.timeline.add("all attempts failed");
        }
        return o;
    }
}
