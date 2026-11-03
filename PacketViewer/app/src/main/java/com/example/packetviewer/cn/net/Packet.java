package com.example.packetviewer.cn.net;

import com.example.packetviewer.cn.utils.TransitionUtils;

/**
 * A parsed IPv4 / IPv6 packet. {@link #parse(byte[])} never throws; when the
 * packet is malformed {@link #error} says why. {@link #verify()} checks the
 * header checksum, the length fields and the TCP/UDP/ICMP checksum.
 */
public final class Packet {

    public final byte[] raw;
    public int version;
    public byte[] src, dst;
    public int proto;          // IPv4 protocol / IPv6 next header (of the base header)
    public int ttl;            // TTL or hop limit
    public int headerLen;      // IP header bytes (IHL*4 or 40)
    public int totalLen;       // IPv4 total length / 40 + IPv6 payload length
    public int tos;            // ToS / traffic class
    public int id;             // IPv4 identification
    public boolean df, mf;
    public int fragOffset;     // in 8-byte units
    public String error;       // null if the packet parsed

    public Packet(byte[] raw) {
        this.raw = raw;
    }

    public static Packet parse(byte[] b) {
        Packet p = new Packet(b);
        if (b == null || b.length < 20) { p.error = "shorter than an IPv4 header"; return p; }
        p.version = (b[0] >> 4) & 0x0F;
        if (p.version == 4) {
            p.headerLen = (b[0] & 0x0F) * 4;
            if (p.headerLen < 20 || b.length < p.headerLen) { p.error = "bad IHL"; return p; }
            p.tos = b[1] & 0xFF;
            p.totalLen = PacketBuilder.get16(b, 2);
            p.id = PacketBuilder.get16(b, 4);
            int ff = PacketBuilder.get16(b, 6);
            p.df = (ff & 0x4000) != 0;
            p.mf = (ff & 0x2000) != 0;
            p.fragOffset = ff & 0x1FFF;
            p.ttl = b[8] & 0xFF;
            p.proto = b[9] & 0xFF;
            p.src = java.util.Arrays.copyOfRange(b, 12, 16);
            p.dst = java.util.Arrays.copyOfRange(b, 16, 20);
            if (p.totalLen > b.length) p.error = "total length " + p.totalLen + " > bytes present " + b.length;
        } else if (p.version == 6) {
            if (b.length < 40) { p.error = "shorter than an IPv6 header"; return p; }
            p.headerLen = 40;
            p.tos = ((b[0] & 0x0F) << 4) | ((b[1] >> 4) & 0x0F);
            p.totalLen = 40 + PacketBuilder.get16(b, 4);
            p.proto = b[6] & 0xFF;
            p.ttl = b[7] & 0xFF;
            p.src = java.util.Arrays.copyOfRange(b, 8, 24);
            p.dst = java.util.Arrays.copyOfRange(b, 24, 40);
            if (p.totalLen > b.length) p.error = "payload length exceeds bytes present";
        } else {
            p.error = "IP version " + p.version;
        }
        return p;
    }

    public boolean isV4() { return version == 4; }

    public int l4Offset() { return headerLen; }

    public int l4Length() { return totalLen - headerLen; }

    public byte[] l4() {
        return java.util.Arrays.copyOfRange(raw, headerLen, totalLen);
    }

    /** Source port (TCP/UDP) or echo identifier (ICMP), -1 otherwise. */
    public int srcPortOrId() {
        if (error != null) return -1;
        if (proto == PacketBuilder.TCP || proto == PacketBuilder.UDP) return PacketBuilder.get16(raw, headerLen);
        if (isEcho()) return PacketBuilder.get16(raw, headerLen + 4);
        return -1;
    }

    public int dstPortOrId() {
        if (error != null) return -1;
        if (proto == PacketBuilder.TCP || proto == PacketBuilder.UDP) return PacketBuilder.get16(raw, headerLen + 2);
        if (isEcho()) return PacketBuilder.get16(raw, headerLen + 4);
        return -1;
    }

    public boolean isEcho() {
        if (error != null || l4Length() < 8) return false;
        int t = raw[headerLen] & 0xFF;
        return (isV4() && proto == PacketBuilder.ICMP && (t == 8 || t == 0))
                || (!isV4() && proto == PacketBuilder.ICMPV6 && (t == 128 || t == 129));
    }

    /** Empty list = fully valid. Otherwise one line per problem found. */
    public java.util.List<String> verify() {
        java.util.List<String> problems = new java.util.ArrayList<>();
        if (error != null) { problems.add(error); return problems; }
        if (totalLen != raw.length) problems.add("length field " + totalLen + " != packet size " + raw.length);
        if (isV4()) {
            if (Checksum.of(raw, 0, headerLen) != 0) problems.add("IPv4 header checksum invalid");
        }
        if (fragOffset == 0 && !mf) {
            int l4len = l4Length();
            if (proto == PacketBuilder.TCP || proto == PacketBuilder.UDP
                    || (isV4() && proto == PacketBuilder.ICMP) || (!isV4() && proto == PacketBuilder.ICMPV6)) {
                if (l4len < 8) { problems.add("L4 header truncated"); return problems; }
                long s = 0;
                if (isV4() && proto != PacketBuilder.ICMP) s = Checksum.pseudoV4(src, dst, proto, l4len);
                if (!isV4()) s = Checksum.pseudoV6(src, dst, proto, l4len);
                boolean udpZero = isV4() && proto == PacketBuilder.UDP && PacketBuilder.get16(raw, headerLen + 6) == 0;
                if (!udpZero && Checksum.finish(Checksum.add(s, raw, headerLen, l4len)) != 0) {
                    problems.add(protoName() + " checksum invalid");
                }
            }
        }
        return problems;
    }

    public String protoName() {
        if (isV4() && proto == PacketBuilder.ICMP) return "ICMP";
        if (!isV4() && proto == PacketBuilder.ICMPV6) return "ICMPv6";
        return TransitionUtils.protoName(proto);
    }

    /** One-line description, e.g. "IPv6 2001:db8::1 -> 64:ff9b::c000:201  UDP 5000->53  len 72  hop 63". */
    public String describe() {
        if (error != null) return "malformed (" + error + ")";
        String a = isV4() ? TransitionUtils.formatIPv4(src) : TransitionUtils.formatIPv6(src);
        String b = isV4() ? TransitionUtils.formatIPv4(dst) : TransitionUtils.formatIPv6(dst);
        StringBuilder sb = new StringBuilder();
        sb.append(isV4() ? "IPv4 " : "IPv6 ").append(a).append(" -> ").append(b).append("  ").append(protoName());
        if (proto == PacketBuilder.TCP || proto == PacketBuilder.UDP) {
            sb.append(' ').append(srcPortOrId()).append("->").append(dstPortOrId());
        } else if (isEcho()) {
            int t = raw[headerLen] & 0xFF;
            sb.append((t == 8 || t == 128) ? " echo-request" : " echo-reply").append(" id=").append(srcPortOrId());
        }
        sb.append("  ").append(raw.length).append(" B  ").append(isV4() ? "ttl " : "hop ").append(ttl);
        return sb.toString();
    }
}
