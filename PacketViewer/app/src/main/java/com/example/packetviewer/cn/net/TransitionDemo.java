package com.example.packetviewer.cn.net;

import com.example.packetviewer.cn.utils.TransitionUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Runs a {@link Scenario} through the real engine and writes the report.
 * Packets are built, translated / encapsulated, re-parsed and checksum-
 * verified; latency and throughput come from {@link PathModel} using
 * per-packet costs measured by {@link Benchmark}.
 */
public final class TransitionDemo {

    public static final int NAT64 = 0, SIX_IN_FOUR = 1, DS_LITE = 2, DUAL_STACK = 3, COMPARE = 4;
    public static final String[] MODE_NAMES = {
            "Translation: NAT64 / DNS64 (IPv6 client -> IPv4 server)",
            "Tunneling: 6in4 (IPv6 over IPv4)",
            "Tunneling: DS-Lite 4in6 (IPv4 over IPv6)",
            "Dual-stack: RFC 6724 + Happy Eyeballs",
            "Compare all mechanisms (latency / throughput)"};

    private TransitionDemo() { }

    public static String run(Scenario s, int mode, Benchmark.Costs c) {
        String err = s.validate();
        if (err != null) return "Input error: " + err;
        StringBuilder sb = new StringBuilder();
        switch (mode) {
            case NAT64: nat64(s, c, sb); break;
            case SIX_IN_FOUR: tunnel(s, c, sb, false); break;
            case DS_LITE: tunnel(s, c, sb, true); break;
            case DUAL_STACK: dual(s, c, sb); break;
            default: compare(s, c, sb); break;
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // NAT64
    // ------------------------------------------------------------------

    private static void nat64(Scenario s, Benchmark.Costs c, StringBuilder sb) {
        byte[] c6 = TransitionUtils.parseIPv6(s.clientV6);
        byte[] srv4 = TransitionUtils.parseIPv4(s.serverV4);
        byte[] pool = TransitionUtils.parseIPv4(s.poolV4);
        Nat64Prefix prefix = new Nat64Prefix(TransitionUtils.parseIPv6(s.nat64Prefix), s.nat64PrefixLen);
        Nat64Translator nat = new Nat64Translator(prefix, pool);
        nat.mtu4 = s.mtu;
        nat.mtu6 = s.mtu;

        title(sb, "NAT64 / DNS64  -  RFC 6052, RFC 7915, RFC 6146");
        byte[] synth = prefix.embed(srv4);
        sb.append("DNS64: ").append(TransitionUtils.formatIPv4(srv4)).append(" has no AAAA record, so the resolver\n")
          .append("synthesises one by embedding it in ").append(TransitionUtils.formatIPv6(prefix.prefix))
          .append("/").append(prefix.length).append(":\n  ")
          .append(TransitionUtils.formatIPv6(synth)).append("\n");
        sb.append("Extracting it again gives ").append(TransitionUtils.formatIPv4(prefix.extract(synth)))
          .append(prefix.length == 64 || prefix.length < 96 ? "  (bits 64-71 'u' octet kept zero)" : "").append("\n");
        if (prefix.isWellKnown() && !TransitionUtils.isGlobalV4(srv4)) {
            sb.append("\nNOTE: the Well-Known Prefix may only embed globally routable IPv4 addresses (RFC 6052 3.1).\n")
              .append("This server address is not global, so the translator will refuse it. Use your own\n")
              .append("prefix (e.g. 2001:db8:64::) or a public server address.\n");
        }
        long now = 0;

        // 1) ICMP echo
        section(sb, "1. Ping through the translator");
        byte[] pay = PacketBuilder.payload(32);
        byte[] ping = PacketBuilder.ipv6(c6, synth, PacketBuilder.ICMPV6, 64,
                PacketBuilder.echo(c6, synth, false, 0x1234, 1, pay));
        show(sb, "client sends", ping);
        Nat64Translator.Result r1 = nat.translate6to4(ping, now += 10);
        steps(sb, r1.steps, r1.drop);
        if (r1.ok()) {
            show(sb, "server receives", r1.packet);
            int id4 = Packet.parse(r1.packet).srcPortOrId();
            byte[] reply = PacketBuilder.ipv4(srv4, pool, PacketBuilder.ICMP, 55, false, 77,
                    PacketBuilder.echo(srv4, pool, true, id4, 1, pay));
            show(sb, "server replies", reply);
            Nat64Translator.Result r2 = nat.translate4to6(reply, now += 10);
            steps(sb, r2.steps, r2.drop);
            if (r2.ok()) show(sb, "client receives", r2.packet);
        }

        // 2) TCP handshake (SYN, SYN/ACK)
        section(sb, "2. TCP connection (SYN, SYN/ACK)");
        byte[] syn = PacketBuilder.ipv6(c6, synth, PacketBuilder.TCP, 64,
                PacketBuilder.tcp(c6, synth, 51000, 443, 1000, 0, 0x02, 65535, new byte[0]));
        show(sb, "client SYN", syn);
        Nat64Translator.Result t1 = nat.translate6to4(syn, now += 10);
        steps(sb, t1.steps, t1.drop);
        if (t1.ok()) {
            show(sb, "server receives SYN", t1.packet);
            int mp = Packet.parse(t1.packet).srcPortOrId();
            byte[] synack = PacketBuilder.ipv4(srv4, pool, PacketBuilder.TCP, 55, false, 78,
                    PacketBuilder.tcp(srv4, pool, 443, mp, 7000, 1001, 0x12, 29200, new byte[0]));
            Nat64Translator.Result t2 = nat.translate4to6(synack, now += 10);
            steps(sb, t2.steps, t2.drop);
            if (t2.ok()) show(sb, "client receives SYN/ACK", t2.packet);
        }

        // 3) UDP
        section(sb, "3. UDP datagram (DNS-sized, 512 B payload)");
        byte[] udpPay = PacketBuilder.payload(512);
        byte[] udp = PacketBuilder.ipv6(c6, synth, PacketBuilder.UDP, 64,
                PacketBuilder.udp(c6, synth, 40000, 53, udpPay));
        Nat64Translator.Result u1 = nat.translate6to4(udp, now += 10);
        sb.append(u1.ok() ? "translated and verified: " + Packet.parse(u1.packet).describe() + "\n"
                          : "DROPPED: " + u1.drop + "\n");

        // 4) policy
        section(sb, "4. Packets a translator must refuse");
        byte[] low = PacketBuilder.ipv6(c6, synth, PacketBuilder.UDP, 1,
                PacketBuilder.udp(c6, synth, 40001, 53, udpPay));
        sb.append("hop limit 1      -> ").append(refusal(nat.translate6to4(low, now += 1))).append("\n");
        byte[] stray = PacketBuilder.ipv4(srv4, pool, PacketBuilder.UDP, 50, false, 5,
                PacketBuilder.udp(srv4, pool, 53, 61000, udpPay));
        sb.append("unsolicited v4   -> ").append(refusal(nat.translate4to6(stray, now += 1))).append("\n");
        byte[] outside = TransitionUtils.parseIPv6("2001:db8:ffff::1");
        byte[] foreign = PacketBuilder.ipv6(c6, outside, PacketBuilder.UDP, 64,
                PacketBuilder.udp(c6, outside, 40002, 53, udpPay));
        sb.append("outside prefix   -> ").append(refusal(nat.translate6to4(foreign, now += 1))).append("\n");
        byte[] corrupt = udp.clone();
        corrupt[corrupt.length - 1] ^= 0x5A;
        sb.append("corrupt payload  -> ").append(refusal(nat.translate6to4(corrupt, now += 1))).append("\n");
        byte[] big = PacketBuilder.ipv6(c6, synth, PacketBuilder.UDP, 64,
                PacketBuilder.udp(c6, synth, 40003, 53, PacketBuilder.payload(s.mtu - 20 - 8 + 1)));
        sb.append("too big for v4   -> ").append(refusal(nat.translate6to4(big, now += 1))).append("\n");

        sb.append("\nBinding table (").append(nat.bindingCount()).append(" entries):\n").append(nat.bindingTable()).append("\n");

        // 5) latency / throughput
        section(sb, "5. Latency and throughput");
        PathModel.Flow base = nativeFlow(s, c, false);
        PathModel.Flow f = flow(s, c, NAT64);
        costs(sb, c);
        sb.append(flowText(f, base));
    }

    // ------------------------------------------------------------------
    // Tunnels
    // ------------------------------------------------------------------

    private static void tunnel(Scenario s, Benchmark.Costs c, StringBuilder sb, boolean dsLite) {
        title(sb, dsLite ? "DS-Lite 4in6  -  RFC 6333 (B4 -> AFTR)" : "6in4  -  RFC 4213 (protocol 41)");
        byte[] inner;
        Tunnels.Result enc;
        byte[] outerSrc, outerDst;
        String innerLabel;
        byte[] payload = PacketBuilder.payload(256);
        if (dsLite) {
            byte[] host = TransitionUtils.parseIPv4(s.hostV4);
            byte[] srv = TransitionUtils.parseIPv4(s.serverV4);
            outerSrc = TransitionUtils.parseIPv6(s.b4V6);
            outerDst = TransitionUtils.parseIPv6(s.aftrV6);
            inner = PacketBuilder.ipv4(host, srv, PacketBuilder.UDP, 64, true, 4242,
                    PacketBuilder.udp(host, srv, 5000, 53, payload));
            innerLabel = "host IPv4 packet";
        } else {
            byte[] cl = TransitionUtils.parseIPv6(s.clientV6);
            byte[] srv = TransitionUtils.parseIPv6(s.serverV6);
            outerSrc = TransitionUtils.parseIPv4(s.tunnelLocalV4);
            outerDst = TransitionUtils.parseIPv4(s.tunnelRemoteV4);
            inner = PacketBuilder.ipv6(cl, srv, PacketBuilder.UDP, 64,
                    PacketBuilder.udp(cl, srv, 5000, 53, payload));
            innerLabel = "client IPv6 packet";
        }
        section(sb, "1. Encapsulate at the tunnel ingress");
        show(sb, innerLabel, inner);
        enc = Tunnels.encap(inner, outerSrc, outerDst, s.mtu, 1);
        steps(sb, enc.steps, enc.drop);
        if (enc.ok()) {
            show(sb, "on the wire", enc.packet);
            sb.append("overhead: ").append(enc.packet.length - inner.length).append(" B per packet (")
              .append(String.format(Locale.US, "%.1f", 100.0 * (enc.packet.length - inner.length) / enc.packet.length))
              .append(" % of this packet)\n");
            section(sb, "2. Decapsulate at the tunnel egress");
            Tunnels.Result dec = Tunnels.decap(enc.packet, outerSrc, outerDst);
            steps(sb, dec.steps, dec.drop);
            if (dec.ok()) show(sb, "delivered", dec.packet);
            if (dsLite) {
                sb.append("The AFTR then applies NAT44 to the inner IPv4 packet (not simulated here, and\n")
                  .append("its CPU cost is NOT included in the figures below).\n");
            }
        }

        section(sb, "3. Packets the tunnel must refuse");
        Tunnels.Result spoof = Tunnels.decap(enc.ok() ? enc.packet : inner, dsLite ? TransitionUtils.parseIPv6("2001:db8:bad::1")
                : TransitionUtils.parseIPv4("192.0.2.66"), outerDst);
        sb.append("wrong tunnel peer -> ").append(spoof.ok() ? "ACCEPTED (bug)" : "dropped: " + spoof.drop).append("\n");
        int room = Tunnels.tunnelMtu(s.mtu, dsLite) - (dsLite ? 20 : 40) - 8;
        byte[] bigInner;
        if (dsLite) {
            byte[] host = TransitionUtils.parseIPv4(s.hostV4), srv = TransitionUtils.parseIPv4(s.serverV4);
            bigInner = PacketBuilder.ipv4(host, srv, PacketBuilder.UDP, 64, true, 1, PacketBuilder.udp(host, srv, 1, 2, PacketBuilder.payload(room + 1)));
        } else {
            byte[] cl = TransitionUtils.parseIPv6(s.clientV6), srv = TransitionUtils.parseIPv6(s.serverV6);
            bigInner = PacketBuilder.ipv6(cl, srv, PacketBuilder.UDP, 64, PacketBuilder.udp(cl, srv, 1, 2, PacketBuilder.payload(room + 1)));
        }
        Tunnels.Result tooBig = Tunnels.encap(bigInner, outerSrc, outerDst, s.mtu, 2);
        sb.append("1 B over tunnel MTU (").append(Tunnels.tunnelMtu(s.mtu, dsLite)).append(") -> ")
          .append(tooBig.ok() ? "ACCEPTED (bug)" : "dropped: " + tooBig.drop).append("\n");

        section(sb, "4. Latency and throughput");
        PathModel.Flow base = nativeFlow(s, c, !dsLite);
        PathModel.Flow f = flow(s, c, dsLite ? DS_LITE : SIX_IN_FOUR);
        costs(sb, c);
        sb.append(flowText(f, base));
    }

    // ------------------------------------------------------------------
    // Dual stack
    // ------------------------------------------------------------------

    private static void dual(Scenario s, Benchmark.Costs c, StringBuilder sb) {
        title(sb, "Dual-stack  -  RFC 6724 address selection + RFC 8305 Happy Eyeballs");
        byte[] a = TransitionUtils.parseIPv4(s.serverV4);
        byte[] aaaa = TransitionUtils.parseIPv6(s.serverV6);
        sb.append("DNS answers for the server:\n  A     ").append(s.serverV4).append("   (path RTT ")
          .append(fmt(s.rtt4Ms)).append(" ms)\n  AAAA  ").append(TransitionUtils.formatIPv6(aaaa))
          .append("   (path RTT ").append(fmt(s.rtt6Ms)).append(" ms")
          .append(s.v6Blackholed ? ", BLACK-HOLED: packets vanish" : "").append(")\n");

        List<DualStack.Candidate> cands = new ArrayList<>();
        cands.add(new DualStack.Candidate(a, s.rtt4Ms, true));          // DNS order: A first on purpose
        cands.add(new DualStack.Candidate(aaaa, s.rtt6Ms, !s.v6Blackholed));
        section(sb, "1. RFC 6724 sorting (policy table precedence)");
        List<DualStack.Candidate> sorted = new ArrayList<>(cands);
        DualStack.sort(sorted);
        for (int i = 0; i < sorted.size(); i++) {
            DualStack.Candidate k = sorted.get(i);
            sb.append("  ").append(i + 1).append(". ").append(k.text()).append("   precedence ").append(k.precedence)
              .append(k.isV6() ? "  (longest matching policy-table prefix)" : "  (looked up as ::ffff:0:0/96)").append("\n");
        }
        section(sb, "2. RFC 8305 connection race (250 ms attempt delay)");
        DualStack.Outcome o = DualStack.race(cands);
        for (String line : o.timeline) sb.append(line).append("\n");

        section(sb, "3. Packets for the winning family");
        if (o.winner != null) {
            byte[] cl6 = TransitionUtils.parseIPv6(s.clientV6);
            byte[] host4 = TransitionUtils.parseIPv4(s.hostV4);
            byte[] syn = o.winner.isV6()
                    ? PacketBuilder.ipv6(cl6, aaaa, PacketBuilder.TCP, 64, PacketBuilder.tcp(cl6, aaaa, 50000, 443, 1, 0, 0x02, 65535, new byte[0]))
                    : PacketBuilder.ipv4(host4, a, PacketBuilder.TCP, 64, true, 9, PacketBuilder.tcp(host4, a, 50000, 443, 1, 0, 0x02, 65535, new byte[0]));
            show(sb, "SYN (no translation, no tunnel)", syn);
        }

        section(sb, "4. Latency and throughput");
        costs(sb, c);
        PathModel.Flow v4 = nativeFlow(s, c, false);
        PathModel.Flow v6 = nativeFlow(s, c, true);
        if (o.winner == null) {
            sb.append("Both families failed - no connection.\n");
            return;
        }
        PathModel.Flow win = o.winner.isV6() ? v6 : v4;
        sb.append(String.format(Locale.US, "Time to first byte of connection: %.1f ms (race result)\n", o.connectMs));
        if (o.winner.isV6() == false && !s.v6Blackholed && s.rtt6Ms > s.rtt4Ms + 0) {
            sb.append("IPv4 won because the IPv6 path is slower than the 250 ms delay allows or slower than IPv4.\n");
        }
        if (s.v6Blackholed) {
            double penalty = o.connectMs - s.rtt4Ms;
            sb.append(String.format(Locale.US, "Broken IPv6 cost %.1f ms of extra connect time (the attempt delay) - without Happy\n"
                    + "Eyeballs a plain connect() would hang for the OS TCP timeout instead.\n", penalty));
        }
        sb.append(flowText(win, win == v4 ? v6 : v4));
        sb.append("(second figure column compares with the other family)\n");
    }

    // ------------------------------------------------------------------
    // Compare
    // ------------------------------------------------------------------

    private static void compare(Scenario s, Benchmark.Costs c, StringBuilder sb) {
        title(sb, "Mechanism comparison, same link and window");
        costs(sb, c);
        sb.append("\nTransfer: ").append(fmt(s.transferMb)).append(" MB over ").append(fmt(s.linkMbps))
          .append(" Mbit/s, loss ").append(fmt(s.lossPct)).append(" %, window ").append(s.windowKb)
          .append(" KB, MTU ").append(s.mtu).append("\n\n");
        PathModel.Flow[] flows = {
                nativeFlow(s, c, false), nativeFlow(s, c, true),
                flow(s, c, NAT64), flow(s, c, SIX_IN_FOUR), flow(s, c, DS_LITE)};
        sb.append(String.format(Locale.US, "%-14s %7s %5s %9s %8s  %s%n", "mechanism", "RTT ms", "MSS", "Mbit/s", "time s", "limited by"));
        double best = Double.POSITIVE_INFINITY;
        for (PathModel.Flow f : flows) best = Math.min(best, f.transferSec);
        for (PathModel.Flow f : flows) {
            sb.append(String.format(Locale.US, "%-14s %7.2f %5d %9.2f %8.2f  %s%s%n", f.name, f.rttMs, f.mss,
                    f.goodputMbps, f.transferSec, f.limiter, f.transferSec == best ? "  <- fastest" : ""));
        }
        PathModel.Flow n6 = flows[1];
        sb.append("\nWhat the numbers say:\n");
        sb.append(String.format(Locale.US, "- Translation / tunnelling processing adds %.3f ms to an RTT (%.2f %% of it): the\n"
                + "  real latency cost is the detour (%s ms) and any longer path, not the CPU work.\n",
                flows[2].processingMs, 100 * flows[2].processingMs / flows[2].rttMs, fmt(s.detourMs)));
        sb.append(String.format(Locale.US, "- Tunnels lose %d B of MSS to the outer header (MSS %d vs %d on native IPv6).\n",
                n6.mss - flows[3].mss, flows[3].mss, n6.mss));
        sb.append(String.format(Locale.US, "- On this device the translator alone could sustain about %.0f Mbit/s of %d B segments;\n"
                + "  a faster link would be CPU-bound first.\n", flows[2].cpuLimitMbps, flows[2].mss));
        sb.append("\nNative IPv4/IPv6 rows are the baseline; the others use the same link but add their\n"
                + "mechanism's detour, header overhead and measured per-packet cost.\n");
    }

    // ------------------------------------------------------------------
    // Flows
    // ------------------------------------------------------------------

    private static PathModel.Flow nativeFlow(Scenario s, Benchmark.Costs c, boolean v6) {
        int hdr = v6 ? 40 : 20;
        return PathModel.compute(v6 ? "native IPv6" : "native IPv4", s.mtu - hdr - 20, hdr,
                v6 ? s.rtt6Ms : s.rtt4Ms, 2 * c.forwardNs, c.forwardNs,
                s.linkMbps, s.lossPct, s.windowKb * 1024, s.transferMb);
    }

    private static PathModel.Flow flow(Scenario s, Benchmark.Costs c, int mech) {
        int win = s.windowKb * 1024;
        switch (mech) {
            case NAT64:
                // v6 client side limits the MSS (v6 header is 20 B bigger than v4 after translation)
                return PathModel.compute("NAT64", s.mtu - 60, 40, s.rtt4Ms + s.detourMs,
                        c.nat64v6to4Ns + c.nat64v4to6Ns, c.nat64v4to6Ns + 0.5 * c.nat64v6to4Ns,
                        s.linkMbps, s.lossPct, win, s.transferMb);
            case SIX_IN_FOUR:
                return PathModel.compute("6in4", s.mtu - 20 - 60, 60, s.rtt6Ms + s.detourMs,
                        2 * (c.encapNs + c.decapNs), Math.max(c.encapNs, c.decapNs),
                        s.linkMbps, s.lossPct, win, s.transferMb);
            default:
                return PathModel.compute("DS-Lite", s.mtu - 40 - 20 - 20, 60, s.rtt4Ms + s.detourMs,
                        2 * (c.encapNs + c.decapNs), Math.max(c.encapNs, c.decapNs),
                        s.linkMbps, s.lossPct, win, s.transferMb);
        }
    }

    private static String flowText(PathModel.Flow f, PathModel.Flow base) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format(Locale.US, "%s: RTT %.2f ms (+%.3f ms processing), MSS %d B\n", f.name, f.rttMs, f.processingMs, f.mss));
        sb.append(String.format(Locale.US, "  limits (Mbit/s): link %.1f | window %.1f | loss %s | CPU %.0f\n",
                f.linkLimitMbps, f.windowLimitMbps,
                Double.isInfinite(f.lossLimitMbps) ? "n/a" : String.format(Locale.US, "%.1f", f.lossLimitMbps), f.cpuLimitMbps));
        sb.append(String.format(Locale.US, "  goodput %.2f Mbit/s (%.0f %% of link), limited by %s\n", f.goodputMbps, f.efficiencyPct, f.limiter));
        sb.append(String.format(Locale.US, "  transfer time %.2f s\n", f.transferSec));
        sb.append(String.format(Locale.US, "vs %s: RTT %+.2f ms, goodput %+.2f Mbit/s, transfer %+.2f s\n",
                base.name, f.rttMs - base.rttMs, f.goodputMbps - base.goodputMbps, f.transferSec - base.transferSec));
        return sb.toString();
    }

    private static void costs(StringBuilder sb, Benchmark.Costs c) {
        sb.append(String.format(Locale.US, "Measured on this device (%d packets of %d B, median of batches):\n"
                        + "  plain forward %.0f ns | NAT64 v6->v4 %.0f ns | NAT64 v4->v6 %.0f ns\n"
                        + "  encapsulate %.0f ns | decapsulate %.0f ns\n",
                c.iterations, c.packetBytes, c.forwardNs, c.nat64v6to4Ns, c.nat64v4to6Ns, c.encapNs, c.decapNs));
    }

    // ------------------------------------------------------------------
    // Text helpers
    // ------------------------------------------------------------------

    private static void title(StringBuilder sb, String t) {
        sb.append("=== ").append(t).append(" ===\n");
    }

    private static void section(StringBuilder sb, String t) {
        sb.append("\n--- ").append(t).append(" ---\n");
    }

    private static void show(StringBuilder sb, String label, byte[] pkt) {
        Packet p = Packet.parse(pkt);
        List<String> bad = p.verify();
        sb.append(label).append(":\n  ").append(p.describe()).append("\n  checksums/lengths: ")
          .append(bad.isEmpty() ? "all valid" : "INVALID (" + bad.get(0) + ")").append("\n");
        int n = Math.min(pkt.length, p.headerLen + 8 + (p.proto == PacketBuilder.TCP ? 12 : 0));
        sb.append(TransitionUtils.hexDump(Arrays.copyOf(pkt, n), "  ")).append("\n");
    }

    private static void steps(StringBuilder sb, List<String> steps, String drop) {
        for (String st : steps) sb.append("  * ").append(st).append("\n");
        if (drop != null) sb.append("  DROPPED: ").append(drop).append("\n");
    }

    private static String refusal(Nat64Translator.Result r) {
        return r.ok() ? "ACCEPTED (unexpected)" : "dropped: " + r.drop;
    }

    private static String fmt(double d) {
        return d == Math.rint(d) ? String.valueOf((long) d) : String.format(Locale.US, "%.2f", d);
    }
}
