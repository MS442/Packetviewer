package com.example.packetviewer.cn.net;

import com.example.packetviewer.cn.utils.TransitionUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Real encapsulation / decapsulation.
 *   6in4  (RFC 4213): IPv6 packet inside IPv4, protocol 41
 *   4in6  (DS-Lite, RFC 6333): IPv4 packet inside IPv6, next header 4
 * The tunnel counts as ONE hop for the inner packet, so the inner TTL / hop
 * limit is decremented on entry (IPv4 checksum updated incrementally).
 */
public final class Tunnels {

    public static final class Result {
        public byte[] packet;       // null if dropped
        public String drop;
        public final List<String> steps = new ArrayList<>();
        public boolean ok() { return packet != null; }
    }

    /** Build the step log; switched off by Benchmark so logging is not measured as processing. */
    public static volatile boolean trace = true;

    private Tunnels() { }

    /** Tunnel MTU = underlying MTU minus the outer header. */
    public static int tunnelMtu(int linkMtu, boolean outerV6) {
        return linkMtu - (outerV6 ? 40 : 20);
    }

    public static Result encap(byte[] inner, byte[] outerSrc, byte[] outerDst, int linkMtu, int id) {
        Result r = new Result();
        boolean outerV6 = outerSrc.length == 16;
        Packet p = Packet.parse(inner);
        if (p.error != null) { r.drop = "malformed inner packet: " + p.error; return r; }
        if (outerV6 != (p.version == 4)) {
            r.drop = outerV6 ? "4in6 needs an IPv4 inner packet" : "6in4 needs an IPv6 inner packet";
            return r;
        }
        List<String> bad = p.verify();
        if (!bad.isEmpty()) { r.drop = "invalid inner packet: " + bad.get(0); return r; }
        if (p.ttl <= 1) { r.drop = "inner TTL/hop limit expires at the tunnel ingress"; return r; }
        byte[] in = inner.clone();
        if (p.version == 4) {
            int oldW = PacketBuilder.get16(in, 8);              // TTL | protocol
            in[8]--;
            int newW = PacketBuilder.get16(in, 8);
            int cs = Checksum.update(PacketBuilder.get16(in, 10), oldW, newW);
            PacketBuilder.put16(in, 10, cs);
            if (trace) r.steps.add("inner TTL " + p.ttl + " -> " + (p.ttl - 1) + ", header checksum updated incrementally");
        } else {
            in[7]--;
            if (trace) r.steps.add("inner hop limit " + p.ttl + " -> " + (p.ttl - 1));
        }
        int tm = tunnelMtu(linkMtu, outerV6);
        if (in.length > tm) {
            r.drop = "inner packet " + in.length + " B > tunnel MTU " + tm + " (link " + linkMtu + " - "
                    + (outerV6 ? 40 : 20) + " B outer header); "
                    + (outerV6 ? "IPv6 cannot be fragmented in transit: ICMPv6 Packet Too Big sent"
                               : (p.df ? "DF=1: ICMP fragmentation needed sent" : "would need fragmentation"));
            return r;
        }
        byte[] out;
        if (outerV6) {
            out = PacketBuilder.ipv6(outerSrc, outerDst, PacketBuilder.IPV4, 64, in);
        } else {
            out = PacketBuilder.ipv4(outerSrc, outerDst, PacketBuilder.IPV6, 64, false, id & 0xFFFF, in);
        }
        if (trace) r.steps.add("prepended " + (outerV6 ? "40 B IPv6" : "20 B IPv4") + " outer header, "
                + (outerV6 ? "next header 4" : "protocol 41") + ", " + in.length + " -> " + out.length + " B");
        r.packet = out;
        return r;
    }

    /** Removes the outer header after checking it is really addressed to this tunnel endpoint. */
    public static Result decap(byte[] outer, byte[] expectSrc, byte[] expectDst) {
        Result r = new Result();
        Packet o = Packet.parse(outer);
        if (o.error != null) { r.drop = "malformed outer packet: " + o.error; return r; }
        boolean outerV6 = o.version == 6;
        int want = outerV6 ? PacketBuilder.IPV4 : PacketBuilder.IPV6;
        if (o.proto != want) { r.drop = "outer protocol/next header " + o.proto + ", expected " + want; return r; }
        if (!Arrays.equals(o.dst, expectDst)) { r.drop = "outer destination is not this tunnel endpoint"; return r; }
        if (!Arrays.equals(o.src, expectSrc)) { r.drop = "outer source " + (outerV6 ? TransitionUtils.formatIPv6(o.src) : TransitionUtils.formatIPv4(o.src))
                + " is not the configured tunnel peer (anti-spoofing)"; return r; }
        if (outerV6 == false && Checksum.of(outer, 0, o.headerLen) != 0) { r.drop = "outer IPv4 header checksum invalid"; return r; }
        if (o.ttl <= 1) { r.drop = "outer TTL/hop limit expired"; return r; }
        byte[] inner = Arrays.copyOfRange(outer, o.headerLen, o.totalLen);
        Packet ip = Packet.parse(inner);
        if (ip.error != null || ip.version != (outerV6 ? 4 : 6)) { r.drop = "inner packet invalid"; return r; }
        List<String> bad = ip.verify();
        if (!bad.isEmpty()) { r.drop = "inner packet invalid: " + bad.get(0); return r; }
        if (trace) r.steps.add("outer header verified (peer, destination, checksum), removed " + o.headerLen + " B");
        r.packet = inner;
        return r;
    }
}
