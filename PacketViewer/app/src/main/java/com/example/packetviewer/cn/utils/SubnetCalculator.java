package com.example.packetviewer.cn.utils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * CIDR subnetting for IPv4 and IPv6 using BigInteger arithmetic:
 * parse "addr/len" or "addr mask", compute network / broadcast / host range,
 * locate an address inside a subnet, split into equal subnets and allocate
 * VLSM subnets (largest first, naturally aligned).
 */
public final class SubnetCalculator {

    public enum Position { OUTSIDE, NETWORK_ADDRESS, BROADCAST_ADDRESS, ROUTER_ANYCAST, HOST }

    /** One subnet. */
    public static final class Subnet {
        public final boolean v6;
        public final int prefixLen;
        public final BigInteger network;
        public final int bits;

        Subnet(boolean v6, int prefixLen, BigInteger anyAddress) {
            this.v6 = v6;
            this.prefixLen = prefixLen;
            this.bits = v6 ? 128 : 32;
            BigInteger mask = maskOf(bits, prefixLen);
            this.network = anyAddress.and(mask);
        }

        public BigInteger size() { return BigInteger.ONE.shiftLeft(bits - prefixLen); }
        public BigInteger last() { return network.add(size()).subtract(BigInteger.ONE); }

        /** Usable hosts: v4 /31 = 2 (RFC 3021), /32 = 1, otherwise size-2; v6 = size (all usable). */
        public BigInteger usableHosts() {
            if (v6) return size();
            if (prefixLen == 32) return BigInteger.ONE;
            if (prefixLen == 31) return BigInteger.valueOf(2);
            return size().subtract(BigInteger.valueOf(2));
        }

        public BigInteger firstHost() {
            if (v6 || prefixLen >= 31) return network;
            return network.add(BigInteger.ONE);
        }

        public BigInteger lastHost() {
            if (v6 || prefixLen >= 31) return last();
            return last().subtract(BigInteger.ONE);
        }

        public String networkText() { return text(network); }
        public String lastText() { return text(last()); }
        public String cidr() { return text(network) + "/" + prefixLen; }

        public String maskText() {
            return v6 ? "/" + prefixLen : text(maskOf(32, prefixLen));
        }

        public String wildcardText() {
            return v6 ? "-" : text(maskOf(32, prefixLen).xor(BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE)));
        }

        public String text(BigInteger v) { return SubnetCalculator.text(v, v6); }

        public boolean contains(BigInteger addr) {
            return addr.compareTo(network) >= 0 && addr.compareTo(last()) <= 0;
        }

        public Position position(BigInteger addr) {
            if (!contains(addr)) return Position.OUTSIDE;
            if (v6) return addr.equals(network) ? Position.ROUTER_ANYCAST : Position.HOST;
            if (prefixLen >= 31) return Position.HOST;      // /31 and /32 have no network/broadcast
            if (addr.equals(network)) return Position.NETWORK_ADDRESS;
            if (addr.equals(last())) return Position.BROADCAST_ADDRESS;
            return Position.HOST;
        }

        public String describe() {
            StringBuilder sb = new StringBuilder();
            sb.append(v6 ? "IPv6" : "IPv4").append(" subnet ").append(cidr()).append('\n');
            sb.append("  mask      : ").append(maskText()).append('\n');
            if (!v6) sb.append("  wildcard  : ").append(wildcardText()).append('\n');
            sb.append("  network   : ").append(networkText()).append('\n');
            if (!v6) sb.append("  broadcast : ").append(prefixLen >= 31 ? "none (/" + prefixLen + ")" : lastText()).append('\n');
            sb.append("  host range: ").append(text(firstHost())).append(" - ").append(text(lastHost())).append('\n');
            sb.append("  addresses : ").append(size()).append("   usable hosts: ").append(usableHosts()).append('\n');
            if (!v6 && prefixLen == 31) sb.append("  note      : /31 point-to-point link, both addresses usable (RFC 3021)\n");
            if (!v6 && prefixLen == 32) sb.append("  note      : /32 single host route\n");
            if (v6 && prefixLen == 64) sb.append("  note      : /64 is the standard IPv6 LAN size (SLAAC needs it)\n");
            return sb.toString();
        }
    }

    /** A VLSM request / allocation. */
    public static final class Allocation {
        public final String label;
        public final int hostsNeeded;
        public final Subnet subnet;
        Allocation(String label, int hostsNeeded, Subnet subnet) {
            this.label = label; this.hostsNeeded = hostsNeeded; this.subnet = subnet;
        }
    }

    private SubnetCalculator() { }

    // ------------------------------------------------------------------
    // Parsing
    // ------------------------------------------------------------------

    /** Address text -> numeric value (null if invalid). Sets v6 via the returned array's length: 4 or 16. */
    public static byte[] parseAddress(String s) {
        byte[] a = TransitionUtils.parseIPv4(s);
        return a != null ? a : TransitionUtils.parseIPv6(s);
    }

    /**
     * Parses "192.168.1.77/26", "192.168.1.77 255.255.255.192" or "2001:db8::1/48".
     * Returns the subnet containing that address, or null if invalid (see {@link #error}).
     */
    public static Subnet parse(String text) {
        Parsed p = parseWithAddress(text);
        return p == null ? null : p.subnet;
    }

    public static final class Parsed {
        public final Subnet subnet;
        public final BigInteger address;
        Parsed(Subnet s, BigInteger a) { subnet = s; address = a; }
    }

    public static Parsed parseWithAddress(String text) {
        if (text == null) return null;
        String t = text.trim();
        String addr;
        String lenPart;
        int slash = t.indexOf('/');
        if (slash >= 0) {
            addr = t.substring(0, slash).trim();
            lenPart = t.substring(slash + 1).trim();
        } else {
            String[] parts = t.split("\\s+");
            if (parts.length != 2) return null;
            addr = parts[0];
            lenPart = parts[1];
        }
        byte[] a = parseAddress(addr);
        if (a == null) return null;
        boolean v6 = a.length == 16;
        int bits = v6 ? 128 : 32;
        int len;
        if (lenPart.contains(".")) {
            if (v6) return null;
            byte[] m = TransitionUtils.parseIPv4(lenPart);
            if (m == null) return null;
            len = prefixFromMask(new BigInteger(1, m));
            if (len < 0) return null;
        } else {
            try { len = Integer.parseInt(lenPart); } catch (NumberFormatException e) { return null; }
            if (len < 0 || len > bits) return null;
        }
        BigInteger v = new BigInteger(1, a);
        return new Parsed(new Subnet(v6, len, v), v);
    }

    /** Human explanation of why parse() returned null. */
    public static String error(String text) {
        if (text == null || text.trim().isEmpty()) return "Enter an address with a prefix, e.g. 192.168.1.77/26";
        String t = text.trim();
        int slash = t.indexOf('/');
        String addr = slash >= 0 ? t.substring(0, slash).trim() : t.split("\\s+")[0];
        byte[] a = parseAddress(addr);
        if (a == null) return "\"" + addr + "\" is not a valid IPv4 or IPv6 address";
        String lenPart = slash >= 0 ? t.substring(slash + 1).trim() : (t.split("\\s+").length > 1 ? t.split("\\s+")[1] : "");
        if (lenPart.isEmpty()) return "Add a prefix length (/26) or a subnet mask";
        if (lenPart.contains(".")) {
            byte[] m = TransitionUtils.parseIPv4(lenPart);
            if (m == null) return "\"" + lenPart + "\" is not a valid mask";
            if (a.length == 16) return "Dotted masks only work for IPv4; use /prefix for IPv6";
            return "Mask " + lenPart + " is not contiguous (ones then zeros)";
        }
        return "Prefix must be 0-" + (a.length == 16 ? 128 : 32);
    }

    static int prefixFromMask(BigInteger mask) {
        int ones = mask.bitCount();
        return maskOf(32, ones).equals(mask) ? ones : -1;
    }

    static BigInteger maskOf(int bits, int prefix) {
        BigInteger all = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE);
        return all.shiftRight(bits - prefix).shiftLeft(bits - prefix).and(all);
    }

    public static String text(BigInteger v, boolean v6) {
        int n = v6 ? 16 : 4;
        byte[] raw = v.toByteArray();
        byte[] b = new byte[n];
        int copy = Math.min(raw.length, n);
        System.arraycopy(raw, raw.length - copy, b, n - copy, copy);
        return v6 ? TransitionUtils.formatIPv6(b) : TransitionUtils.formatIPv4(b);
    }

    // ------------------------------------------------------------------
    // Split / VLSM
    // ------------------------------------------------------------------

    /** Splits into equal subnets of newPrefix. Returns at most maxCount; null if newPrefix is invalid. */
    public static List<Subnet> split(Subnet parent, int newPrefix, int maxCount) {
        if (newPrefix <= parent.prefixLen || newPrefix > parent.bits) return null;
        List<Subnet> out = new ArrayList<>();
        BigInteger step = BigInteger.ONE.shiftLeft(parent.bits - newPrefix);
        BigInteger cur = parent.network;
        BigInteger end = parent.last();
        while (cur.compareTo(end) <= 0 && out.size() < maxCount) {
            out.add(new Subnet(parent.v6, newPrefix, cur));
            cur = cur.add(step);
        }
        return out;
    }

    /** Number of subnets a split would create, as text (can be huge for IPv6). */
    public static String splitCount(Subnet parent, int newPrefix) {
        return BigInteger.ONE.shiftLeft(newPrefix - parent.prefixLen).toString();
    }

    /** Smallest prefix that holds the hosts (v4 counts network+broadcast; /31 and /32 only when exactly 2/1). */
    public static int prefixForHosts(boolean v6, long hosts) {
        int bits = v6 ? 128 : 32;
        for (int p = bits; p >= 0; p--) {
            BigInteger size = BigInteger.ONE.shiftLeft(bits - p);
            BigInteger usable = v6 ? size : (p == 32 ? BigInteger.ONE : p == 31 ? BigInteger.valueOf(2) : size.subtract(BigInteger.valueOf(2)));
            if (usable.compareTo(BigInteger.valueOf(hosts)) >= 0) return p;
        }
        return 0;
    }

    /**
     * VLSM: allocate one subnet per request (largest first) from the parent block,
     * each aligned to its own size. Returns null and sets failure[0] if the block runs out.
     */
    public static List<Allocation> vlsm(Subnet parent, List<String> labels, List<Integer> hosts, String[] failure) {
        List<Integer> order = new ArrayList<>();
        for (int i = 0; i < hosts.size(); i++) order.add(i);
        Collections.sort(order, (x, y) -> Integer.compare(hosts.get(y), hosts.get(x)));
        List<Allocation> result = new ArrayList<>();
        BigInteger cursor = parent.network;
        for (int idx : order) {
            int p = prefixForHosts(parent.v6, hosts.get(idx));
            if (p < parent.prefixLen) { failure[0] = labels.get(idx) + " needs " + hosts.get(idx) + " hosts: larger than the parent block"; return null; }
            BigInteger size = BigInteger.ONE.shiftLeft(parent.bits - p);
            // align the cursor up to a multiple of size
            BigInteger rem = cursor.mod(size);
            if (rem.signum() != 0) cursor = cursor.add(size.subtract(rem));
            if (cursor.add(size).subtract(BigInteger.ONE).compareTo(parent.last()) > 0) {
                failure[0] = "Out of space in " + parent.cidr() + " at \"" + labels.get(idx) + "\" (" + hosts.get(idx) + " hosts)";
                return null;
            }
            result.add(new Allocation(labels.get(idx), hosts.get(idx), new Subnet(parent.v6, p, cursor)));
            cursor = cursor.add(size);
        }
        return result;
    }

    public static String vlsmReport(Subnet parent, List<Allocation> allocs) {
        StringBuilder sb = new StringBuilder("VLSM inside " + parent.cidr() + " (largest first):\n");
        BigInteger used = BigInteger.ZERO;
        for (Allocation a : allocs) {
            Subnet s = a.subnet;
            sb.append(String.format(Locale.US, "  %-10s need %-6d -> %s  hosts %s - %s  (%s usable)%n",
                    a.label, a.hostsNeeded, s.cidr(), s.text(s.firstHost()), s.text(s.lastHost()), s.usableHosts()));
            used = used.add(s.size());
        }
        sb.append("Used ").append(used).append(" of ").append(parent.size()).append(" addresses (")
          .append(String.format(Locale.US, "%.1f", 100.0 * used.doubleValue() / parent.size().doubleValue())).append(" %)\n");
        return sb.toString();
    }
}
