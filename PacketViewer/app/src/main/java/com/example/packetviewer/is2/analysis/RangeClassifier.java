package com.example.packetviewer.is2.analysis;

import com.example.packetviewer.cn.utils.TransitionUtils;
import com.example.packetviewer.cn.utils.TransitionUtils.V6Kind;

/**
 * FIS input 1: "Range". Looks at WHICH address block an address belongs to
 * (RFC 6890 special-purpose registry) and turns it into a 0-100 score:
 *
 *    0   ordinary public unicast address
 *   ~50  valid only on private / limited networks (RFC 1918, ULA, CGNAT...)
 *   ~100 block that can never be a normal host address (loopback, multicast,
 *        documentation, Class E, unallocated IPv6 space...)
 *
 * The same private address is perfectly normal on a LAN but a classic
 * "bogon" (spoofing indicator) as a source on the public Internet, so the
 * score depends on the Scenario the user picks.
 *
 * Pure Java (no Android classes) so it can be unit-tested on the JVM.
 */
public final class RangeClassifier {

    private RangeClassifier() { }

    /** Where the address is expected to be seen. */
    public enum Scenario { INTERNET, LAN }

    public enum Kind {
        PUBLIC, PRIVATE, SHARED, LINK_LOCAL, LOOPBACK, THIS_NETWORK, DOCUMENTATION, BENCHMARK,
        PROTOCOL, ANYCAST_6TO4, MULTICAST, BROADCAST, RESERVED, MAPPED, TRANSLATION, TUNNEL, UNALLOCATED
    }

    public static final class Result {
        public final Kind kind;
        public final double score;
        public final String reason;

        Result(Kind kind, double score, String reason) {
            this.kind = kind;
            this.score = score;
            this.reason = reason;
        }

        /** True if this kind of address can never legitimately appear as a packet's SOURCE. */
        public boolean invalidAsSource() {
            switch (kind) {
                case THIS_NETWORK:
                case LOOPBACK:
                case MULTICAST:
                case BROADCAST:
                case RESERVED:
                    return true;
                default:
                    return false;
            }
        }
    }

    // ------------------------------------------------------------------
    // IPv4 (RFC 6890, RFC 1918, RFC 6598, RFC 5737, RFC 1112)
    // ------------------------------------------------------------------

    public static Result classifyV4(byte[] a, Scenario scenario) {
        int a0 = a[0] & 0xFF, a1 = a[1] & 0xFF, a2 = a[2] & 0xFF, a3 = a[3] & 0xFF;
        boolean lan = scenario == Scenario.LAN;

        if (a0 == 0) {
            return new Result(Kind.THIS_NETWORK, 95,
                    "0.0.0.0/8 'this network': only valid as a source while a host is booting (DHCP)");
        }
        if (a0 == 10) return privateV4(lan, "10.0.0.0/8");
        if (a0 == 100 && a1 >= 64 && a1 <= 127) {
            return new Result(Kind.SHARED, 40,
                    "100.64.0.0/10 shared address space (RFC 6598, carrier-grade NAT): valid only inside an ISP");
        }
        if (a0 == 127) {
            return new Result(Kind.LOOPBACK, 100,
                    "127.0.0.0/8 loopback: only ever refers to the sending host itself");
        }
        if (a0 == 169 && a1 == 254) {
            return lan
                    ? new Result(Kind.LINK_LOCAL, 20,
                    "169.254.0.0/16 link-local (APIPA): self-assigned when DHCP fails, valid on one link only")
                    : new Result(Kind.LINK_LOCAL, 70,
                    "169.254.0.0/16 link-local: never routed, so it cannot be a genuine Internet source");
        }
        if (a0 == 172 && a1 >= 16 && a1 <= 31) return privateV4(lan, "172.16.0.0/12");
        if (a0 == 192 && a1 == 0 && a2 == 0) {
            return new Result(Kind.PROTOCOL, 75, "192.0.0.0/24 IETF protocol assignments: not for ordinary hosts");
        }
        if (a0 == 192 && a1 == 0 && a2 == 2) return documentationV4("192.0.2.0/24 (TEST-NET-1)");
        if (a0 == 192 && a1 == 88 && a2 == 99) {
            return new Result(Kind.ANYCAST_6TO4, 70, "192.88.99.0/24 deprecated 6to4 relay anycast (RFC 7526)");
        }
        if (a0 == 192 && a1 == 168) return privateV4(lan, "192.168.0.0/16");
        if (a0 == 198 && (a1 == 18 || a1 == 19)) {
            return new Result(Kind.BENCHMARK, 75,
                    "198.18.0.0/15 network benchmarking (RFC 2544): never on the real Internet");
        }
        if (a0 == 198 && a1 == 51 && a2 == 100) return documentationV4("198.51.100.0/24 (TEST-NET-2)");
        if (a0 == 203 && a1 == 0 && a2 == 113) return documentationV4("203.0.113.0/24 (TEST-NET-3)");
        if (a0 >= 224 && a0 <= 239) {
            return new Result(Kind.MULTICAST, 95, "224.0.0.0/4 multicast: a group address, not a single host");
        }
        if (a0 == 255 && a1 == 255 && a2 == 255 && a3 == 255) {
            return new Result(Kind.BROADCAST, 100, "255.255.255.255 limited broadcast: never a host address");
        }
        if (a0 >= 240) {
            return new Result(Kind.RESERVED, 100, "240.0.0.0/4 reserved for future use (Class E): never assigned");
        }
        return new Result(Kind.PUBLIC, 0, "public unicast block: no reserved-range problem found");
    }

    private static Result privateV4(boolean lan, String block) {
        return lan
                ? new Result(Kind.PRIVATE, 0, block + " private (RFC 1918): normal on a local network")
                : new Result(Kind.PRIVATE, 50, block + " private (RFC 1918): not routable on the public Internet, "
                + "so as an Internet source it is a 'bogon' (typical spoof or misconfiguration)");
    }

    private static Result documentationV4(String block) {
        return new Result(Kind.DOCUMENTATION, 85, block + " documentation range (RFC 5737): reserved for examples, never routed");
    }

    // ------------------------------------------------------------------
    // IPv6 (RFC 4291, RFC 4193, RFC 3849, RFC 6052, RFC 6890)
    // ------------------------------------------------------------------

    public static Result classifyV6(byte[] a, Scenario scenario) {
        boolean lan = scenario == Scenario.LAN;
        V6Kind k = TransitionUtils.classifyV6(a);
        switch (k) {
            case UNSPECIFIED:
                return new Result(Kind.THIS_NETWORK, 95,
                        ":: unspecified address: only valid as a source during start-up (duplicate address detection)");
            case LOOPBACK:
                return new Result(Kind.LOOPBACK, 100, "::1 loopback: only ever refers to the sending host itself");
            case IPV4_MAPPED:
                return new Result(Kind.MAPPED, 90,
                        "::ffff:0:0/96 IPv4-mapped: exists only inside a host's sockets, never on the wire");
            case NAT64:
                return new Result(Kind.TRANSLATION, 30,
                        "64:ff9b::/96 NAT64 prefix: valid only inside an IPv6-only network with a NAT64 gateway");
            case SIX_TO_FOUR: {
                byte[] v4 = TransitionUtils.embeddedV4(a, k);
                Result inner = classifyV4(v4, Scenario.INTERNET);
                if (inner.kind != Kind.PUBLIC) {
                    return new Result(Kind.TUNNEL, 85, "2002::/16 6to4 address that embeds the non-public IPv4 "
                            + TransitionUtils.formatIPv4(v4) + " (" + inner.kind + "): invalid");
                }
                return new Result(Kind.TUNNEL, 35, "2002::/16 6to4 tunnel address (deprecated, RFC 7526)");
            }
            case TEREDO:
                return new Result(Kind.TUNNEL, 30, "2001::/32 Teredo tunnel address (deprecated)");
            case DOCUMENTATION:
                return new Result(Kind.DOCUMENTATION, 85,
                        "2001:db8::/32 documentation prefix (RFC 3849): reserved for examples, never routed");
            case LINK_LOCAL:
                return lan
                        ? new Result(Kind.LINK_LOCAL, 20, "fe80::/10 link-local: normal on one link, never routed")
                        : new Result(Kind.LINK_LOCAL, 70,
                        "fe80::/10 link-local: never routed, so it cannot be a genuine Internet source");
            case ULA:
                return lan
                        ? new Result(Kind.PRIVATE, 0, "fc00::/7 unique-local (RFC 4193): IPv6 'private' space, normal on a LAN")
                        : new Result(Kind.PRIVATE, 50, "fc00::/7 unique-local (RFC 4193): not routable on the public "
                        + "Internet, so as an Internet source it is a 'bogon'");
            case MULTICAST:
                return new Result(Kind.MULTICAST, 95, "ff00::/8 multicast: a group address, not a single host");
            case GLOBAL:
                // 2001:2::/48 is reserved for benchmarking, inside the otherwise-global 2000::/3.
                if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x00 && a[3] == 0x02 && a[4] == 0 && a[5] == 0) {
                    return new Result(Kind.BENCHMARK, 75, "2001:2::/48 network benchmarking (RFC 5180): never on the real Internet");
                }
                return new Result(Kind.PUBLIC, 0, "global unicast block (2000::/3): no reserved-range problem found");
            default:
                return new Result(Kind.UNALLOCATED, 90,
                        "outside 2000::/3: not currently allocated as global unicast space");
        }
    }
}
