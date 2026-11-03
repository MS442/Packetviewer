package com.example.packetviewer.cn.net;

import com.example.packetviewer.cn.utils.TransitionUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Stateful NAT64 (RFC 6146) with SIIT header translation (RFC 7915).
 *
 * Works on raw packet bytes: IPv6 -> IPv4 creates / refreshes a binding
 * (client addr+port -> pool addr + allocated port), rewrites the header and
 * the L4 checksum; IPv4 -> IPv6 looks the binding up by destination port,
 * applies address-dependent filtering, and rewrites back. Anything this demo
 * cannot translate correctly is DROPPED with a reason, never faked.
 *
 * Supported: TCP, UDP, ICMP echo, no extension headers, no fragments.
 */
public final class Nat64Translator {

    /** Outcome of translating one packet; steps is a real log of what was done. */
    public static final class Result {
        public byte[] packet;                 // null if dropped
        public String drop;                   // reason if dropped
        public final List<String> steps = new ArrayList<>();
        public boolean ok() { return packet != null; }
    }

    private static final class Binding {
        int proto;
        byte[] v6;
        int v6Port;
        int v4Port;
        long lastUsed;
        final Set<Integer> remotes = new HashSet<>();   // v4 peers this client has talked to
    }

    public final Nat64Prefix prefix;
    public final byte[] pool;       // the translator's IPv4 address
    public int mtu4 = 1500;
    public int mtu6 = 1500;

    public long udpTimeoutMs = 5 * 60_000L;       // RFC 4787 / 6146 defaults
    public long icmpTimeoutMs = 60_000L;
    public long tcpTimeoutMs = 2 * 60 * 60_000L + 4 * 60_000L;

    private final Map<String, Binding> forward = new HashMap<>();   // proto|v6|port
    private final Map<String, Binding> reverse = new HashMap<>();   // proto|v4port
    private final int[] nextPort = new int[256];
    private int nextId = 1;

    public int translated, dropped;
    /** Build the human-readable step log. Off while benchmarking so logging is not counted as processing. */
    public boolean trace = true;

    public Nat64Translator(Nat64Prefix prefix, byte[] poolV4) {
        this.prefix = prefix;
        this.pool = poolV4.clone();
        Arrays.fill(nextPort, 1024);
    }

    public int bindingCount() { return forward.size(); }

    // ------------------------------------------------------------------
    // IPv6 -> IPv4
    // ------------------------------------------------------------------

    public Result translate6to4(byte[] in, long nowMs) {
        Result r = new Result();
        expire(nowMs);
        Packet p = Packet.parse(in);
        if (p.error != null || p.version != 6) return drop(r, p.error != null ? "malformed: " + p.error : "not an IPv6 packet");
        List<String> bad = p.verify();
        if (!bad.isEmpty()) return drop(r, "invalid input: " + bad.get(0));
        if (trace) r.steps.add("parsed " + p.describe());
        if (p.ttl <= 1) return drop(r, "hop limit " + p.ttl + " would expire (a real translator sends ICMPv6 Time Exceeded)");
        if (!prefix.contains(p.dst)) return drop(r, "destination " + TransitionUtils.formatIPv6(p.dst) + " is outside the NAT64 prefix");
        byte[] v4dst = prefix.extract(p.dst);
        if (trace) r.steps.add("RFC 6052: extracted IPv4 destination " + TransitionUtils.formatIPv4(v4dst)
                + " from /" + prefix.length + " prefix");
        if (prefix.isWellKnown() && !TransitionUtils.isGlobalV4(v4dst)) {
            return drop(r, TransitionUtils.formatIPv4(v4dst) + " is not globally routable; RFC 6052 forbids it behind 64:ff9b::/96");
        }
        int proto = p.proto;
        if (proto == PacketBuilder.TCP || proto == PacketBuilder.UDP || proto == PacketBuilder.ICMPV6) {
            if (proto == PacketBuilder.ICMPV6 && !p.isEcho()) return drop(r, "only ICMPv6 echo is translated here");
            if (proto == PacketBuilder.ICMPV6 && (in[40] & 0xFF) != 128) return drop(r, "ICMPv6 echo reply from the v6 side has no binding");
        } else {
            return drop(r, "next header " + proto + " not supported (extension header / unsupported protocol)");
        }
        int l4proto = (proto == PacketBuilder.ICMPV6) ? PacketBuilder.ICMP : proto;
        int clientId = p.srcPortOrId();

        Binding b = forward.get(fkey(l4proto, p.src, clientId));
        boolean created = false;
        if (b == null) {
            b = allocate(l4proto, p.src, clientId);
            if (b == null) return drop(r, "port pool exhausted");
            created = true;
        }
        b.lastUsed = nowMs;
        b.remotes.add(v4key(v4dst));
        if (trace) r.steps.add((created ? "new binding " : "existing binding ")
                + "[" + TransitionUtils.formatIPv6(p.src) + "]:" + clientId + " <-> "
                + TransitionUtils.formatIPv4(pool) + ":" + b.v4Port);

        byte[] l4 = p.l4();
        if (l4proto == PacketBuilder.ICMP) {
            l4[0] = 8;                                   // ICMPv6 echo request (128) -> ICMP echo request (8)
            PacketBuilder.put16(l4, 4, b.v4Port);
            PacketBuilder.put16(l4, 2, 0);
            PacketBuilder.put16(l4, 2, Checksum.of(l4, 0, l4.length));
            if (trace) r.steps.add("ICMPv6 128 -> ICMP 8, identifier rewritten, checksum recomputed (no pseudo-header in ICMPv4)");
        } else {
            int csOff = (l4proto == PacketBuilder.TCP) ? 16 : 6;
            int cs = PacketBuilder.get16(l4, csOff);
            cs = Checksum.updateBytes(cs, p.src, 0, 16, pool, 0, 4);
            cs = Checksum.updateBytes(cs, p.dst, 0, 16, v4dst, 0, 4);
            cs = Checksum.update(cs, clientId, b.v4Port);
            if (l4proto == PacketBuilder.UDP && cs == 0) cs = 0xFFFF;
            PacketBuilder.put16(l4, 0, b.v4Port);
            PacketBuilder.put16(l4, csOff, cs);
            if (trace) r.steps.add("source port " + clientId + " -> " + b.v4Port + ", checksum updated incrementally (RFC 1624)");
        }
        byte[] hdr = TransitionUtils.buildIPv4Header(pool, v4dst, l4proto, p.ttl - 1, p.tos,
                20 + l4.length, nextId++ & 0xFFFF, true);
        byte[] out = PacketBuilder.concat(hdr, l4);
        if (trace) r.steps.add("IPv6 header (40 B) -> IPv4 header (20 B): TC->ToS, hop " + p.ttl + "->TTL " + (p.ttl - 1)
                + ", DF=1, new header checksum");
        if (out.length > mtu4) {
            return drop(r, "translated size " + out.length + " B exceeds IPv4 MTU " + mtu4
                    + " (real NAT64 would send ICMPv6 Packet Too Big, MTU " + (mtu4 + 20) + ")");
        }
        r.packet = out;
        translated++;
        return r;
    }

    // ------------------------------------------------------------------
    // IPv4 -> IPv6
    // ------------------------------------------------------------------

    public Result translate4to6(byte[] in, long nowMs) {
        Result r = new Result();
        expire(nowMs);
        Packet p = Packet.parse(in);
        if (p.error != null || p.version != 4) return drop(r, p.error != null ? "malformed: " + p.error : "not an IPv4 packet");
        List<String> bad = p.verify();
        if (!bad.isEmpty()) return drop(r, "invalid input: " + bad.get(0));
        if (trace) r.steps.add("parsed " + p.describe());
        if (!Arrays.equals(p.dst, pool)) return drop(r, "destination is not the NAT64 pool address " + TransitionUtils.formatIPv4(pool));
        if (p.ttl <= 1) return drop(r, "TTL " + p.ttl + " would expire (real translator sends ICMP Time Exceeded)");
        if (p.mf || p.fragOffset != 0) return drop(r, "IPv4 fragments are not reassembled in this demo");
        int proto = p.proto;
        if (proto != PacketBuilder.TCP && proto != PacketBuilder.UDP && proto != PacketBuilder.ICMP) {
            return drop(r, "protocol " + proto + " not supported");
        }
        if (proto == PacketBuilder.ICMP && (!p.isEcho() || (in[p.headerLen] & 0xFF) != 0)) {
            return drop(r, "only ICMP echo reply is translated inbound");
        }
        int port = p.dstPortOrId();
        Binding b = reverse.get(rkey(proto, port));
        if (b == null) return drop(r, "no binding for " + TransitionUtils.formatIPv4(pool) + ":" + port
                + " (unsolicited inbound traffic is rejected)");
        if (!b.remotes.contains(v4key(p.src))) {
            return drop(r, "address-dependent filtering: client never sent to " + TransitionUtils.formatIPv4(p.src));
        }
        b.lastUsed = nowMs;
        if (trace) r.steps.add("binding hit: " + TransitionUtils.formatIPv4(pool) + ":" + port + " -> ["
                + TransitionUtils.formatIPv6(b.v6) + "]:" + b.v6Port);

        byte[] src6 = prefix.embed(p.src);
        byte[] l4 = p.l4();
        if (proto == PacketBuilder.ICMP) {
            l4[0] = (byte) 129;
            PacketBuilder.put16(l4, 4, b.v6Port);
            PacketBuilder.put16(l4, 2, 0);
            PacketBuilder.put16(l4, 2, PacketBuilder.l4Checksum(src6, b.v6, PacketBuilder.ICMPV6, l4));
            if (trace) r.steps.add("ICMP 0 -> ICMPv6 129, identifier restored, checksum recomputed WITH the IPv6 pseudo-header");
        } else {
            int csOff = (proto == PacketBuilder.TCP) ? 16 : 6;
            int cs;
            if (proto == PacketBuilder.UDP && PacketBuilder.get16(l4, 6) == 0) {
                PacketBuilder.put16(l4, 2, b.v6Port);
                cs = PacketBuilder.l4Checksum(src6, b.v6, PacketBuilder.UDP, l4);
                if (cs == 0) cs = 0xFFFF;
                if (trace) r.steps.add("IPv4 UDP checksum was 0 (absent): computed one, mandatory in IPv6");
            } else {
                cs = PacketBuilder.get16(l4, csOff);
                cs = Checksum.updateBytes(cs, p.src, 0, 4, src6, 0, 16);
                cs = Checksum.updateBytes(cs, p.dst, 0, 4, b.v6, 0, 16);
                cs = Checksum.update(cs, port, b.v6Port);
                if (proto == PacketBuilder.UDP && cs == 0) cs = 0xFFFF;
                if (trace) r.steps.add("destination port " + port + " -> " + b.v6Port + ", checksum updated incrementally (RFC 1624)");
            }
            PacketBuilder.put16(l4, 2, b.v6Port);
            PacketBuilder.put16(l4, csOff, cs);
        }
        int nh = (proto == PacketBuilder.ICMP) ? PacketBuilder.ICMPV6 : proto;
        byte[] hdr = TransitionUtils.buildIPv6Header(src6, b.v6, nh, p.ttl - 1, p.tos, 0, l4.length);
        byte[] out = PacketBuilder.concat(hdr, l4);
        if (trace) r.steps.add("IPv4 header -> IPv6 header: source " + TransitionUtils.formatIPv4(p.src) + " -> "
                + TransitionUtils.formatIPv6(src6) + ", TTL " + p.ttl + "->hop " + (p.ttl - 1));
        if (out.length > mtu6) {
            return drop(r, "translated size " + out.length + " B exceeds IPv6 MTU " + mtu6);
        }
        r.packet = out;
        translated++;
        return r;
    }

    // ------------------------------------------------------------------
    // Binding table
    // ------------------------------------------------------------------

    private Binding allocate(int proto, byte[] v6, int v6Port) {
        int start = nextPort[proto];
        int port = start;
        do {
            if (!reverse.containsKey(rkey(proto, port))) {
                Binding b = new Binding();
                b.proto = proto;
                b.v6 = v6.clone();
                b.v6Port = v6Port;
                b.v4Port = port;
                forward.put(fkey(proto, v6, v6Port), b);
                reverse.put(rkey(proto, port), b);
                nextPort[proto] = port >= 65535 ? 1024 : port + 1;
                return b;
            }
            port = port >= 65535 ? 1024 : port + 1;
        } while (port != start);
        return null;
    }

    private void expire(long now) {
        List<String> dead = new ArrayList<>();
        for (Map.Entry<String, Binding> e : forward.entrySet()) {
            Binding b = e.getValue();
            long limit = b.proto == PacketBuilder.UDP ? udpTimeoutMs
                    : b.proto == PacketBuilder.TCP ? tcpTimeoutMs : icmpTimeoutMs;
            if (now - b.lastUsed > limit) dead.add(e.getKey());
        }
        for (String k : dead) {
            Binding b = forward.remove(k);
            reverse.remove(rkey(b.proto, b.v4Port));
        }
    }

    /** Human-readable binding table. */
    public String bindingTable() {
        if (forward.isEmpty()) return "  (empty)";
        StringBuilder sb = new StringBuilder();
        for (Binding b : forward.values()) {
            sb.append("  ").append(TransitionUtils.protoName(b.proto)).append("  [")
                    .append(TransitionUtils.formatIPv6(b.v6)).append("]:").append(b.v6Port)
                    .append("  <->  ").append(TransitionUtils.formatIPv4(pool)).append(':').append(b.v4Port)
                    .append("  peers ").append(peers(b)).append('\n');
        }
        return sb.toString().replaceAll("\\n$", "");
    }

    private static String peers(Binding b) {
        StringBuilder sb = new StringBuilder("[");
        for (int k : b.remotes) {
            if (sb.length() > 1) sb.append(", ");
            sb.append((k >>> 24) & 0xFF).append('.').append((k >>> 16) & 0xFF).append('.')
              .append((k >>> 8) & 0xFF).append('.').append(k & 0xFF);
        }
        return sb.append(']').toString();
    }

    private Result drop(Result r, String reason) {
        r.drop = reason;
        r.packet = null;
        dropped++;
        return r;
    }

    private static String fkey(int proto, byte[] v6, int port) {
        char[] c = new char[16 + 2];
        for (int i = 0; i < 16; i++) c[i] = (char) (v6[i] & 0xFF);
        c[16] = (char) proto;
        c[17] = (char) port;
        return new String(c);
    }

    private static int v4key(byte[] a) {
        return ((a[0] & 0xFF) << 24) | ((a[1] & 0xFF) << 16) | ((a[2] & 0xFF) << 8) | (a[3] & 0xFF);
    }

    private static String rkey(int proto, int port) {
        return proto + "|" + port;
    }
}
