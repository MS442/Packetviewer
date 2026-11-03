package com.example.packetviewer.cn.net;

/**
 * Builds complete, valid packets (IP header + L4 + payload) with correct
 * checksums. These are the real bytes that get translated / tunnelled.
 */
public final class PacketBuilder {

    public static final int ICMP = 1, TCP = 6, UDP = 17, IPV4 = 4, IPV6 = 41, ICMPV6 = 58;

    private PacketBuilder() { }

    // ---------- L4 segments (checksum filled in for the given IP family) ----------

    /** UDP datagram with a valid checksum. v4=true uses the IPv4 pseudo-header. */
    public static byte[] udp(byte[] src, byte[] dst, int sport, int dport, byte[] payload) {
        byte[] u = new byte[8 + payload.length];
        put16(u, 0, sport);
        put16(u, 2, dport);
        put16(u, 4, u.length);
        System.arraycopy(payload, 0, u, 8, payload.length);
        int c = l4Checksum(src, dst, UDP, u);
        if (c == 0) c = 0xFFFF;               // 0 means "no checksum" in UDP
        put16(u, 6, c);
        return u;
    }

    /** Minimal 20-byte-header TCP segment. */
    public static byte[] tcp(byte[] src, byte[] dst, int sport, int dport, long seq, long ack,
                             int flags, int window, byte[] payload) {
        byte[] t = new byte[20 + payload.length];
        put16(t, 0, sport);
        put16(t, 2, dport);
        put32(t, 4, seq);
        put32(t, 8, ack);
        t[12] = (byte) 0x50;                  // data offset 5 words
        t[13] = (byte) flags;
        put16(t, 14, window);
        System.arraycopy(payload, 0, t, 20, payload.length);
        put16(t, 16, l4Checksum(src, dst, TCP, t));
        return t;
    }

    /** ICMPv4 (type 8 request / 0 reply) or ICMPv6 (128 / 129) echo. */
    public static byte[] echo(byte[] src, byte[] dst, boolean reply, int ident, int seq, byte[] payload) {
        boolean v6 = src.length == 16;
        byte[] m = new byte[8 + payload.length];
        m[0] = (byte) (v6 ? (reply ? 129 : 128) : (reply ? 0 : 8));
        put16(m, 4, ident);
        put16(m, 6, seq);
        System.arraycopy(payload, 0, m, 8, payload.length);
        put16(m, 2, l4Checksum(src, dst, v6 ? ICMPV6 : ICMP, m));
        return m;
    }

    /** Checksum of an L4 segment whose checksum field is currently zero. */
    public static int l4Checksum(byte[] src, byte[] dst, int proto, byte[] seg) {
        long s;
        if (src.length == 4) {
            s = (proto == ICMP) ? 0 : Checksum.pseudoV4(src, dst, proto, seg.length);
        } else {
            s = Checksum.pseudoV6(src, dst, proto, seg.length);
        }
        return Checksum.finish(Checksum.add(s, seg, 0, seg.length));
    }

    // ---------- IP packets ----------

    public static byte[] ipv4(byte[] src, byte[] dst, int proto, int ttl, boolean df, int id, byte[] l4) {
        byte[] h = com.example.packetviewer.cn.utils.TransitionUtils.buildIPv4Header(
                src, dst, proto, ttl, 0, 20 + l4.length, id, df);
        return concat(h, l4);
    }

    public static byte[] ipv6(byte[] src, byte[] dst, int nh, int hop, byte[] l4) {
        byte[] h = com.example.packetviewer.cn.utils.TransitionUtils.buildIPv6Header(
                src, dst, nh, hop, 0, 0, l4.length);
        return concat(h, l4);
    }

    // ---------- helpers ----------

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    public static void put16(byte[] b, int off, int v) {
        b[off] = (byte) (v >> 8);
        b[off + 1] = (byte) v;
    }

    public static void put32(byte[] b, int off, long v) {
        b[off] = (byte) (v >> 24);
        b[off + 1] = (byte) (v >> 16);
        b[off + 2] = (byte) (v >> 8);
        b[off + 3] = (byte) v;
    }

    public static int get16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    public static byte[] payload(int n) {
        byte[] p = new byte[n];
        for (int i = 0; i < n; i++) p[i] = (byte) ('a' + (i % 23));
        return p;
    }
}
