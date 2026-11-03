package com.example.packetviewer.is2.analysis;

import com.example.packetviewer.cn.utils.SubnetCalculator;
import com.example.packetviewer.cn.utils.SubnetCalculator.Position;
import com.example.packetviewer.cn.utils.SubnetCalculator.Subnet;

import java.math.BigInteger;

/**
 * STEP 0 of the IS2 pipeline: work out which subnet the address belongs to
 * BEFORE the duplicate check and the fuzzy analysis. The subnet decides
 *  - what "duplicate" means (same address in the same subnet), and
 *  - whether the address can be a host at all (network / broadcast address).
 *
 * Uses the CN section's SubnetCalculator, so both sections share one engine.
 */
public final class SubnetStep {

    public static final int AUTO_V4 = 24;
    public static final int AUTO_V6 = 64;

    public static final class Result {
        public final Subnet subnet;           // null when error != null
        public final Position position;
        public final boolean assumed;         // prefix not given: default used
        public final String error;

        Result(Subnet s, Position p, boolean assumed, String error) {
            this.subnet = s; this.position = p; this.assumed = assumed; this.error = error;
        }

        public int prefixLen() { return subnet == null ? -1 : subnet.prefixLen; }
        public String network() { return subnet == null ? "" : subnet.networkText(); }

        /** True when the address cannot be assigned to a host in this subnet. */
        public boolean notAHost() {
            return position == Position.NETWORK_ADDRESS || position == Position.BROADCAST_ADDRESS;
        }

        public String positionText() {
            switch (position) {
                case NETWORK_ADDRESS: return "the NETWORK address (identifies the subnet, not a host)";
                case BROADCAST_ADDRESS: return "the BROADCAST address (not assignable to a host)";
                case ROUTER_ANYCAST: return "the subnet-router anycast address (reserved for routers, RFC 4291)";
                default: return "a normal host address";
            }
        }
    }

    private SubnetStep() { }

    /**
     * @param prefixText "" (auto), "26", "/26", or a dotted IPv4 mask
     */
    public static Result run(byte[] addr, String prefixText) {
        boolean v6 = addr.length == 16;
        String p = prefixText == null ? "" : prefixText.trim();
        boolean assumed = p.isEmpty();
        String full;
        if (assumed) {
            full = (v6 ? com.example.packetviewer.cn.utils.TransitionUtils.formatIPv6(addr)
                       : com.example.packetviewer.cn.utils.TransitionUtils.formatIPv4(addr))
                    + "/" + (v6 ? AUTO_V6 : AUTO_V4);
        } else {
            String addrText = v6 ? com.example.packetviewer.cn.utils.TransitionUtils.formatIPv6(addr)
                                 : com.example.packetviewer.cn.utils.TransitionUtils.formatIPv4(addr);
            full = p.contains(".") ? addrText + " " + p : addrText + "/" + (p.startsWith("/") ? p.substring(1) : p);
        }
        SubnetCalculator.Parsed parsed = SubnetCalculator.parseWithAddress(full);
        if (parsed == null) {
            return new Result(null, Position.OUTSIDE, assumed,
                    "Invalid prefix \"" + p + "\": use /0-" + (v6 ? 128 : 32) + (v6 ? "" : " or a mask like 255.255.255.0"));
        }
        BigInteger v = parsed.address;
        return new Result(parsed.subnet, parsed.subnet.position(v), assumed, null);
    }

    /** Text block for the report (STEP 0). */
    public static String report(Result r) {
        StringBuilder sb = new StringBuilder("=== STEP 0 - SUBNETTING (before duplicate check) ===\n");
        sb.append("Subnet    : ").append(r.subnet.cidr())
          .append(r.assumed ? "  (no prefix given: assumed /" + r.subnet.prefixLen + ")" : "").append('\n');
        if (!r.subnet.v6) {
            sb.append("Mask      : ").append(r.subnet.maskText()).append("   broadcast: ")
              .append(r.subnet.prefixLen >= 31 ? "none" : r.subnet.lastText()).append('\n');
        }
        sb.append("Host range: ").append(r.subnet.text(r.subnet.firstHost())).append(" - ")
          .append(r.subnet.text(r.subnet.lastHost())).append("   (").append(r.subnet.usableHosts()).append(" usable)\n");
        sb.append("Position  : the address is ").append(r.positionText()).append('\n');
        if (r.notAHost()) {
            sb.append("Effect    : Range score raised to at least ").append((int) minRange(r))
              .append(" because this address cannot be a host here.\n");
        }
        sb.append("Duplicate : checked per subnet, so the same address in a different subnet is a different entry.\n\n");
        return sb.toString();
    }

    /** Minimum Range score implied by the address position (0 when no effect). */
    public static double minRange(Result r) {
        if (r == null || r.subnet == null) return 0;
        switch (r.position) {
            case NETWORK_ADDRESS:
            case BROADCAST_ADDRESS: return 85;
            case ROUTER_ANYCAST: return 55;
            default: return 0;
        }
    }

    public static String rangeNote(Result r) {
        return "is " + r.positionText() + " of " + r.subnet.cidr();
    }
}
