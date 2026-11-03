package com.example.packetviewer.cn.utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Low-level building blocks for the IPv6 Transition Mechanisms tab.
 *
 * Everything here is static and pure Java (no Android classes), so it
 * can be unit-tested on the JVM:
 *  - strict IPv4 / IPv6 text -> byte[] parsing (incl. "::ffff:1.2.3.4" forms)
 *  - RFC 5952 style IPv6 formatting
 *  - classification of an address (mapped, NAT64, 6to4, Teredo, ...)
 *  - building raw IPv4 / IPv6 headers (with a real One's Complement checksum)
 *  - raw header builders (the translation engine itself is in cn/net)
 *
 * Reuses PacketParserUtils for the IPv4 checksum so the same CN logic
 * powers the CN section and, through the header check, the IS2 detector.
 */
public final class TransitionUtils {

    private TransitionUtils() { }


    public static final int PROTO_ICMP = 1;
    public static final int PROTO_IPV4 = 4;     // IPv4-in-IPv6 (4in6 / DS-Lite)
    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;
    public static final int PROTO_IPV6 = 41;    // IPv6-in-IPv4 (6in4 / 6to4)
    public static final int PROTO_ICMPV6 = 58;

    // ------------------------------------------------------------------
    // ADDRESS CLASSIFICATION
    // ------------------------------------------------------------------

    public enum V6Kind {
        UNSPECIFIED("Unspecified (::)"),
        LOOPBACK("Loopback (::1)"),
        IPV4_MAPPED("IPv4-mapped (::ffff:0:0/96)"),
        NAT64("NAT64 well-known prefix (64:ff9b::/96)"),
        SIX_TO_FOUR("6to4 (2002::/16)"),
        TEREDO("Teredo (2001::/32)"),
        DOCUMENTATION("Documentation (2001:db8::/32)"),
        LINK_LOCAL("Link-local (fe80::/10)"),
        ULA("Unique local (fc00::/7)"),
        MULTICAST("Multicast (ff00::/8)"),
        GLOBAL("Global unicast (2000::/3)"),
        OTHER("Other / reserved");

        public final String label;

        V6Kind(String label) {
            this.label = label;
        }
    }

    private static boolean allZero(byte[] a, int start, int end) {
        for (int i = start; i < end; i++) {
            if (a[i] != 0) return false;
        }
        return true;
    }

    public static V6Kind classifyV6(byte[] a) {
        if (allZero(a, 0, 16)) return V6Kind.UNSPECIFIED;
        if (allZero(a, 0, 15) && a[15] == 1) return V6Kind.LOOPBACK;
        if (allZero(a, 0, 10) && (a[10] & 0xFF) == 0xFF && (a[11] & 0xFF) == 0xFF) return V6Kind.IPV4_MAPPED;
        if (a[0] == 0x00 && a[1] == 0x64 && (a[2] & 0xFF) == 0xFF && (a[3] & 0xFF) == 0x9B
                && allZero(a, 4, 12)) return V6Kind.NAT64;
        if (a[0] == 0x20 && a[1] == 0x02) return V6Kind.SIX_TO_FOUR;
        if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x00 && a[3] == 0x00) return V6Kind.TEREDO;
        if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0D && (a[3] & 0xFF) == 0xB8) return V6Kind.DOCUMENTATION;
        if ((a[0] & 0xFF) == 0xFE && (a[1] & 0xC0) == 0x80) return V6Kind.LINK_LOCAL;
        if ((a[0] & 0xFE) == 0xFC) return V6Kind.ULA;
        if ((a[0] & 0xFF) == 0xFF) return V6Kind.MULTICAST;
        if ((a[0] & 0xE0) == 0x20) return V6Kind.GLOBAL;
        return V6Kind.OTHER;
    }

    /**
     * The IPv4 address hidden inside an IPv6 address, or null if the
     * address kind doesn't carry one. For Teredo this is the client's
     * (de-obfuscated) public IPv4 - Teredo stores it bit-inverted.
     */
    public static byte[] embeddedV4(byte[] a, V6Kind kind) {
        switch (kind) {
            case IPV4_MAPPED:
            case NAT64:
                return Arrays.copyOfRange(a, 12, 16);
            case SIX_TO_FOUR:
                return Arrays.copyOfRange(a, 2, 6);
            case TEREDO:
                return new byte[]{(byte) ~a[12], (byte) ~a[13], (byte) ~a[14], (byte) ~a[15]};
            default:
                return null;
        }
    }

    public static String describeV4(byte[] a) {
        int a0 = a[0] & 0xFF, a1 = a[1] & 0xFF, a2 = a[2] & 0xFF;
        if (a0 == 10) return "private (RFC 1918, 10.0.0.0/8)";
        if (a0 == 172 && a1 >= 16 && a1 <= 31) return "private (RFC 1918, 172.16.0.0/12)";
        if (a0 == 192 && a1 == 168) return "private (RFC 1918, 192.168.0.0/16)";
        if (a0 == 100 && a1 >= 64 && a1 <= 127) return "shared CGNAT space (100.64.0.0/10)";
        if (a0 == 127) return "loopback (127.0.0.0/8)";
        if (a0 == 169 && a1 == 254) return "link-local (169.254.0.0/16)";
        if ((a0 == 192 && a1 == 0 && a2 == 2) || (a0 == 198 && a1 == 51 && a2 == 100)
                || (a0 == 203 && a1 == 0 && a2 == 113)) return "documentation range (RFC 5737)";
        if (a0 >= 224 && a0 <= 239) return "multicast";
        if (a0 == 0 || a0 >= 240) return "reserved";
        return "public";
    }

    public static boolean isGlobalV4(byte[] a) {
        return "public".equals(describeV4(a));
    }

    // ------------------------------------------------------------------
    // PARSING (text -> bytes)
    // ------------------------------------------------------------------

    /** Dotted-decimal IPv4 -> 4 bytes, or null if invalid. */
    public static byte[] parseIPv4(String text) {
        if (!PacketParserUtils.isValidIPv4(text)) return null;
        String[] p = text.trim().split("\\.");
        byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) b[i] = (byte) Integer.parseInt(p[i]);
        return b;
    }

    /**
     * Strict IPv6 text -> 16 bytes, or null if invalid.
     * Accepts compressed ("2001:db8::1"), full, and dotted-tail
     * ("::ffff:192.0.2.1", "64:ff9b::192.0.2.1") notation. Unlike the
     * simple regex in PacketParserUtils this rejects things like
     * "1::2::3" (two "::") and groups longer than 4 hex digits.
     */
    public static byte[] parseIPv6(String input) {
        if (input == null) return null;
        String s = input.trim().toLowerCase(Locale.US);
        if (s.isEmpty() || !s.contains(":")) return null;

        // Optional IPv4 tail -> rewrite as two hex groups.
        int lastColon = s.lastIndexOf(':');
        String tail = s.substring(lastColon + 1);
        if (tail.contains(".")) {
            byte[] t = parseIPv4(tail);
            if (t == null) return null;
            s = s.substring(0, lastColon + 1)
                    + String.format(Locale.US, "%x:%x",
                    ((t[0] & 0xFF) << 8) | (t[1] & 0xFF),
                    ((t[2] & 0xFF) << 8) | (t[3] & 0xFF));
        }

        int dbl = s.indexOf("::");
        if (dbl != s.lastIndexOf("::")) return null; // more than one "::" (also catches ":::")

        List<String> head = new ArrayList<>();
        List<String> rest = new ArrayList<>();
        if (dbl >= 0) {
            String left = s.substring(0, dbl);
            String right = s.substring(dbl + 2);
            if (!left.isEmpty()) head = Arrays.asList(left.split(":", -1));
            if (!right.isEmpty()) rest = Arrays.asList(right.split(":", -1));
            if (head.size() + rest.size() > 7) return null;
        } else {
            head = Arrays.asList(s.split(":", -1));
            if (head.size() != 8) return null;
        }

        int[] groups = new int[8];
        int idx = 0;
        for (String g : head) {
            int v = hexGroup(g);
            if (v < 0) return null;
            groups[idx++] = v;
        }
        idx = 8 - rest.size();
        for (String g : rest) {
            int v = hexGroup(g);
            if (v < 0) return null;
            groups[idx++] = v;
        }

        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[2 * i] = (byte) (groups[i] >> 8);
            out[2 * i + 1] = (byte) groups[i];
        }
        return out;
    }

    private static int hexGroup(String g) {
        if (g.isEmpty() || g.length() > 4) return -1;
        int v = 0;
        for (int i = 0; i < g.length(); i++) {
            int d = Character.digit(g.charAt(i), 16);
            if (d < 0) return -1;
            v = (v << 4) | d;
        }
        return v;
    }

    // ------------------------------------------------------------------
    // FORMATTING (bytes -> text)
    // ------------------------------------------------------------------

    public static String formatIPv4(byte[] b) {
        return (b[0] & 0xFF) + "." + (b[1] & 0xFF) + "." + (b[2] & 0xFF) + "." + (b[3] & 0xFF);
    }

    /** RFC 5952 compressed form: lowercase, no leading zeros, longest zero run -> "::". */
    public static String formatIPv6(byte[] b) {
        int[] g = groupsOf(b);
        int bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
        for (int i = 0; i < 8; i++) {
            if (g[i] == 0) {
                if (curStart < 0) {
                    curStart = i;
                    curLen = 0;
                }
                curLen++;
                if (curLen > bestLen) {
                    bestLen = curLen;
                    bestStart = curStart;
                }
            } else {
                curStart = -1;
            }
        }
        if (bestLen < 2) bestStart = -1; // a single 0 group is never compressed

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i == bestStart) {
                sb.append("::");
                i += bestLen - 1;
                continue;
            }
            if (sb.length() > 0 && sb.charAt(sb.length() - 1) != ':') sb.append(':');
            sb.append(Integer.toHexString(g[i]));
        }
        return sb.toString();
    }

    /** Fully expanded form: 8 groups of 4 hex digits. */
    public static String formatIPv6Full(byte[] b) {
        int[] g = groupsOf(b);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format(Locale.US, "%04x", g[i]));
        }
        return sb.toString();
    }

    private static int[] groupsOf(byte[] b) {
        int[] g = new int[8];
        for (int i = 0; i < 8; i++) g[i] = ((b[2 * i] & 0xFF) << 8) | (b[2 * i + 1] & 0xFF);
        return g;
    }

    /** Hex dump in 32-bit words, 4 words (16 bytes) per line. */
    public static String hexDump(byte[] b, String indent) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i += 4) {
            if (i % 16 == 0) {
                if (i > 0) sb.append('\n');
                sb.append(indent);
            } else {
                sb.append(' ');
            }
            for (int j = i; j < Math.min(i + 4, b.length); j++) {
                sb.append(String.format(Locale.US, "%02X", b[j] & 0xFF));
            }
        }
        return sb.toString();
    }

    public static String protoName(int p) {
        switch (p) {
            case PROTO_ICMP: return "ICMP";
            case PROTO_IPV4: return "IPv4";
            case PROTO_TCP: return "TCP";
            case PROTO_UDP: return "UDP";
            case PROTO_IPV6: return "IPv6";
            case PROTO_ICMPV6: return "ICMPv6";
            default: return "proto " + p;
        }
    }

    /** Two-line field summary of a 20-byte IPv4 header (kept short for narrow phone screens). */
    public static String summarizeIPv4(byte[] h, String indent) {
        int totalLen = ((h[2] & 0xFF) << 8) | (h[3] & 0xFF);
        int id = ((h[4] & 0xFF) << 8) | (h[5] & 0xFF);
        boolean df = (h[6] & 0x40) != 0;
        int proto = h[9] & 0xFF;
        return indent + String.format(Locale.US, "ver=%d ihl=%d tos=0x%02X len=%d csum=0x%04X",
                (h[0] >>> 4) & 0x0F, h[0] & 0x0F, h[1] & 0xFF, totalLen, ipv4ChecksumField(h))
                + "\n" + indent + String.format(Locale.US, "id=0x%04X%s ttl=%d proto=%d(%s)",
                id, df ? " DF" : "", h[8] & 0xFF, proto, protoName(proto));
    }

    /** Two-line field summary of a 40-byte IPv6 base header. */
    public static String summarizeIPv6(byte[] h, String indent) {
        int tc = ((h[0] & 0x0F) << 4) | ((h[1] & 0xF0) >>> 4);
        int flow = ((h[1] & 0x0F) << 16) | ((h[2] & 0xFF) << 8) | (h[3] & 0xFF);
        int plen = ((h[4] & 0xFF) << 8) | (h[5] & 0xFF);
        int nh = h[6] & 0xFF;
        return indent + String.format(Locale.US, "ver=%d tc=0x%02X flow=0x%05X plen=%d",
                (h[0] >>> 4) & 0x0F, tc, flow, plen)
                + "\n" + indent + String.format(Locale.US, "nh=%d(%s) hl=%d",
                nh, protoName(nh), h[7] & 0xFF);
    }

    public static int ipv4ChecksumField(byte[] h) {
        return ((h[10] & 0xFF) << 8) | (h[11] & 0xFF);
    }

    // ------------------------------------------------------------------
    // WELL-KNOWN ADDRESS CONSTRUCTION
    // ------------------------------------------------------------------

    /** RFC 6052 well-known prefix: 64:ff9b::/96 followed by the 32-bit IPv4 address. */
    public static byte[] nat64Address(byte[] v4) {
        byte[] a = new byte[16];
        a[1] = 0x64;
        a[2] = (byte) 0xFF;
        a[3] = (byte) 0x9B;
        System.arraycopy(v4, 0, a, 12, 4);
        return a;
    }

    /** RFC 4291 IPv4-mapped address ::ffff:a.b.c.d (never appears on the wire). */
    public static byte[] ipv4MappedAddress(byte[] v4) {
        byte[] a = new byte[16];
        a[10] = (byte) 0xFF;
        a[11] = (byte) 0xFF;
        System.arraycopy(v4, 0, a, 12, 4);
        return a;
    }

    /** RFC 3056 6to4 address: 2002:AABB:CCDD:<subnet>::<host>. */
    public static byte[] sixToFourAddress(byte[] v4, int subnet, int host) {
        byte[] a = new byte[16];
        a[0] = 0x20;
        a[1] = 0x02;
        System.arraycopy(v4, 0, a, 2, 4);
        a[6] = (byte) (subnet >> 8);
        a[7] = (byte) subnet;
        a[14] = (byte) (host >> 8);
        a[15] = (byte) host;
        return a;
    }

    /** Dotted-tail display, e.g. "64:ff9b::192.0.2.1" - how RFC 6052 writes NAT64 addresses. */
    public static String nat64Display(byte[] v4) {
        return "64:ff9b::" + formatIPv4(v4);
    }

    // ------------------------------------------------------------------
    // RAW HEADER BUILDERS
    // ------------------------------------------------------------------

    /** 20-byte IPv4 header (no options) with a correct header checksum. */
    public static byte[] buildIPv4Header(byte[] src, byte[] dst, int protocol, int ttl, int tos,
                                         int totalLength, int identification, boolean dontFragment) {
        byte[] h = new byte[20];
        h[0] = 0x45;                                   // version 4, IHL 5
        h[1] = (byte) tos;
        h[2] = (byte) (totalLength >> 8);
        h[3] = (byte) totalLength;
        h[4] = (byte) (identification >> 8);
        h[5] = (byte) identification;
        h[6] = (byte) (dontFragment ? 0x40 : 0x00);    // flags: DF
        h[7] = 0;                                      // fragment offset
        h[8] = (byte) ttl;
        h[9] = (byte) protocol;
        System.arraycopy(src, 0, h, 12, 4);
        System.arraycopy(dst, 0, h, 16, 4);
        int csum = PacketParserUtils.calculateIPv4Checksum(h); // skips bytes 10-11
        h[10] = (byte) (csum >> 8);
        h[11] = (byte) csum;
        return h;
    }

    /** 40-byte IPv6 base header (no extension headers). */
    public static byte[] buildIPv6Header(byte[] src, byte[] dst, int nextHeader, int hopLimit,
                                         int trafficClass, int flowLabel, int payloadLength) {
        byte[] h = new byte[40];
        h[0] = (byte) (0x60 | ((trafficClass >> 4) & 0x0F));
        h[1] = (byte) (((trafficClass & 0x0F) << 4) | ((flowLabel >> 16) & 0x0F));
        h[2] = (byte) (flowLabel >> 8);
        h[3] = (byte) flowLabel;
        h[4] = (byte) (payloadLength >> 8);
        h[5] = (byte) payloadLength;
        h[6] = (byte) nextHeader;
        h[7] = (byte) hopLimit;
        System.arraycopy(src, 0, h, 8, 16);
        System.arraycopy(dst, 0, h, 24, 16);
        return h;
    }
}
