package com.example.packetviewer.cn.net;

import com.example.packetviewer.cn.utils.TransitionUtils;

/**
 * Everything the Transition tool needs, all user-editable. The defaults are
 * only starting values for the input fields (documentation / example
 * addresses and typical home-broadband numbers); every figure in the report
 * is computed from whatever is in these fields.
 */
public final class Scenario {
    // addresses
    public String clientV6 = "2001:db8:1::100";     // IPv6-only client
    public String serverV4 = "93.184.216.34";       // IPv4-only (or dual-stack) server
    public String serverV6 = "2001:db8:2::80";      // server's IPv6 address (6in4 peer / dual-stack AAAA)
    public String poolV4 = "198.51.100.7";          // NAT64 translator IPv4 address
    public String nat64Prefix = "64:ff9b::";        // RFC 6052 prefix
    public int nat64PrefixLen = 96;
    public String tunnelLocalV4 = "198.51.100.1";   // 6in4 ingress
    public String tunnelRemoteV4 = "203.0.113.9";   // 6in4 egress
    public String hostV4 = "192.168.1.10";          // host behind a DS-Lite B4
    public String b4V6 = "2001:db8:b4::2";
    public String aftrV6 = "2001:db8:aa::1";
    // path numbers
    public double rtt4Ms = 40;
    public double rtt6Ms = 35;
    public double detourMs = 15;       // extra RTT to reach the translator / tunnel endpoint / AFTR
    public double linkMbps = 100;
    public double lossPct = 0.05;
    public int mtu = 1500;
    public int windowKb = 256;
    public double transferMb = 10;
    public boolean v6Blackholed = false;

    /** Returns null if everything parses, otherwise the first problem. */
    public String validate() {
        if (TransitionUtils.parseIPv6(clientV6) == null) return "Client IPv6 address is not valid";
        if (TransitionUtils.parseIPv4(serverV4) == null) return "Server IPv4 address is not valid";
        if (TransitionUtils.parseIPv6(serverV6) == null) return "Server IPv6 address is not valid";
        if (TransitionUtils.parseIPv4(poolV4) == null) return "NAT64 pool IPv4 address is not valid";
        if (TransitionUtils.parseIPv6(nat64Prefix) == null) return "NAT64 prefix is not a valid IPv6 address";
        boolean okLen = false;
        for (int l : Nat64Prefix.LENGTHS) okLen |= l == nat64PrefixLen;
        if (!okLen) return "NAT64 prefix length must be 32, 40, 48, 56, 64 or 96";
        if (TransitionUtils.parseIPv4(tunnelLocalV4) == null) return "6in4 local IPv4 is not valid";
        if (TransitionUtils.parseIPv4(tunnelRemoteV4) == null) return "6in4 remote IPv4 is not valid";
        if (TransitionUtils.parseIPv4(hostV4) == null) return "DS-Lite host IPv4 is not valid";
        if (TransitionUtils.parseIPv6(b4V6) == null) return "DS-Lite B4 IPv6 is not valid";
        if (TransitionUtils.parseIPv6(aftrV6) == null) return "DS-Lite AFTR IPv6 is not valid";
        if (rtt4Ms <= 0 || rtt6Ms <= 0) return "RTTs must be above 0 ms";
        if (detourMs < 0) return "Detour cannot be negative";
        if (linkMbps <= 0) return "Link rate must be above 0";
        if (lossPct < 0 || lossPct >= 100) return "Loss must be 0 to <100 %";
        if (mtu < 1280 || mtu > 9000) return "MTU must be between 1280 and 9000";
        if (windowKb < 1) return "TCP window must be at least 1 KB";
        if (transferMb <= 0) return "Transfer size must be above 0";
        return null;
    }
}
