package com.example.packetviewer.cn.net;

import com.example.packetviewer.cn.utils.TransitionUtils;

import java.util.Arrays;

/**
 * Measures how long THIS device takes to process one packet through each
 * mechanism (real translate / encap / decap / forward calls on real bytes).
 * Median of several batches, after a warm-up, so one GC pause or JIT
 * hiccup does not skew the figure. The numbers feed PathModel.
 */
public final class Benchmark {

    /** Nanoseconds per packet. */
    public static final class Costs {
        public double forwardNs;    // plain router: verify header, TTL--, checksum update
        public double nat64v6to4Ns;
        public double nat64v4to6Ns;
        public double encapNs;      // 6in4 and 4in6 averaged
        public double decapNs;
        public int packetBytes;
        public int iterations;
    }

    private static volatile long sink;   // keeps the JIT from deleting the work

    public static Costs run(int payloadBytes, int batch, int rounds) {
        byte[] c6 = TransitionUtils.parseIPv6("2001:db8::100");
        byte[] srv4 = TransitionUtils.parseIPv4("93.184.216.34");
        byte[] pool = TransitionUtils.parseIPv4("198.51.100.7");
        Nat64Prefix wk = Nat64Prefix.wellKnown();
        byte[] dst6 = wk.embed(srv4);
        byte[] pay = PacketBuilder.payload(payloadBytes);

        byte[] out6 = PacketBuilder.ipv6(c6, dst6, PacketBuilder.UDP, 64,
                PacketBuilder.udp(c6, dst6, 40000, 5000, pay));
        // IPv4 reply that the translator will accept (needs the binding created by out6)
        Nat64Translator nat = new Nat64Translator(wk, pool);
        nat.trace = false;
        boolean oldTrace = Tunnels.trace;
        Tunnels.trace = false;
        Nat64Translator.Result first = nat.translate6to4(out6, 0);
        int mappedPort = Packet.parse(first.packet).srcPortOrId();
        byte[] in4 = PacketBuilder.ipv4(srv4, pool, PacketBuilder.UDP, 55, false, 7,
                PacketBuilder.udp(srv4, pool, 5000, mappedPort, pay));

        byte[] v4pkt = PacketBuilder.ipv4(srv4, TransitionUtils.parseIPv4("10.0.0.2"), PacketBuilder.UDP, 64, false, 1,
                PacketBuilder.udp(srv4, TransitionUtils.parseIPv4("10.0.0.2"), 1, 2, pay));
        byte[] t1 = TransitionUtils.parseIPv4("192.0.2.1"), t2 = TransitionUtils.parseIPv4("192.0.2.2");
        byte[] encapped = Tunnels.encap(out6, t1, t2, 1500, 1).packet;

        Costs c = new Costs();
        c.packetBytes = out6.length;
        c.iterations = batch * rounds;

        // warm-up
        for (int i = 0; i < batch * 2; i++) {
            nat.translate6to4(out6, 1);
            nat.translate4to6(in4, 1);
            Tunnels.encap(out6, t1, t2, 1500, i);
            Tunnels.decap(encapped, t1, t2);
            forward(v4pkt);
        }
        c.forwardNs = median(batch, rounds, 0, nat, out6, in4, v4pkt, encapped, t1, t2);
        c.nat64v6to4Ns = median(batch, rounds, 1, nat, out6, in4, v4pkt, encapped, t1, t2);
        c.nat64v4to6Ns = median(batch, rounds, 2, nat, out6, in4, v4pkt, encapped, t1, t2);
        c.encapNs = median(batch, rounds, 3, nat, out6, in4, v4pkt, encapped, t1, t2);
        c.decapNs = median(batch, rounds, 4, nat, out6, in4, v4pkt, encapped, t1, t2);
        Tunnels.trace = oldTrace;
        return c;
    }

    private static double median(int batch, int rounds, int what, Nat64Translator nat, byte[] out6,
                                 byte[] in4, byte[] v4pkt, byte[] encapped, byte[] t1, byte[] t2) {
        double[] per = new double[rounds];
        for (int r = 0; r < rounds; r++) {
            long t0 = System.nanoTime();
            long acc = 0;
            for (int i = 0; i < batch; i++) {
                switch (what) {
                    case 0: acc += forward(v4pkt); break;
                    case 1: acc += nat.translate6to4(out6, 1).packet.length; break;
                    case 2: acc += nat.translate4to6(in4, 1).packet.length; break;
                    case 3: acc += Tunnels.encap(out6, t1, t2, 1500, i).packet.length; break;
                    default: acc += Tunnels.decap(encapped, t1, t2).packet.length; break;
                }
            }
            long t1n = System.nanoTime();
            sink += acc;
            per[r] = (t1n - t0) / (double) batch;
        }
        Arrays.sort(per);
        return per[rounds / 2];
    }

    /** What a plain IPv4 router does per packet: verify the header checksum, TTL--, patch checksum. */
    private static int forward(byte[] pkt) {
        byte[] b = pkt.clone();
        if (Checksum.of(b, 0, 20) != 0) return 0;
        int oldW = PacketBuilder.get16(b, 8);
        b[8]--;
        PacketBuilder.put16(b, 10, Checksum.update(PacketBuilder.get16(b, 10), oldW, PacketBuilder.get16(b, 8)));
        return b.length;
    }
}
