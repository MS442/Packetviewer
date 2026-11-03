package com.example.packetviewer.cn.net;

/**
 * Analytical latency / throughput model for one TCP flow. Every input is a
 * number the user typed or a per-packet cost measured by {@link Benchmark};
 * nothing here is a canned result.
 *
 *   MSS       = hop MTU - IP header - 20 (TCP), minimum over the path
 *   wire/seg  = MSS + 20 + IP header on the link (incl. any tunnel header) + 38 (Ethernet framing)
 *   goodput   = min( link rate x MSS/wire,
 *                    window / RTT,
 *                    Mathis: 1.22 x MSS / (RTT x sqrt(loss)),
 *                    CPU: MSS / (per-segment processing time) )
 *   RTT       = path RTT + detour to the middlebox + 2 x measured processing per direction
 *   transfer  = connect (1 RTT) + slow-start rounds + remaining bytes / goodput
 */
public final class PathModel {

    public static final int ETHERNET_OVERHEAD = 38;   // preamble 8 + header 14 + FCS 4 + IFG 12

    public static final class Flow {
        public String name;
        public int mss;
        public int ipBytesOnLink;
        public double rttMs;
        public double processingMs;   // per RTT, from the benchmark
        public double linkLimitMbps, windowLimitMbps, lossLimitMbps, cpuLimitMbps;
        public double goodputMbps;
        public String limiter;
        public double efficiencyPct;  // goodput / link rate
        public double connectMs;
        public double transferSec;
    }

    private PathModel() { }

    /**
     * @param procNsPerRtt     measured processing per round trip (both directions), ns
     * @param cpuNsPerSegment  measured processing per data segment on the busiest box, ns (0 = none)
     */
    public static Flow compute(String name, int mss, int ipBytesOnLink, double baseRttMs,
                               double procNsPerRtt, double cpuNsPerSegment,
                               double linkMbps, double lossPct, int windowBytes, double transferMb) {
        Flow f = new Flow();
        f.name = name;
        f.mss = mss;
        f.ipBytesOnLink = ipBytesOnLink;
        f.processingMs = procNsPerRtt / 1e6;
        f.rttMs = baseRttMs + f.processingMs;

        double wire = mss + 20 + ipBytesOnLink + ETHERNET_OVERHEAD;
        f.linkLimitMbps = linkMbps * mss / wire;
        double rttSec = f.rttMs / 1000.0;
        f.windowLimitMbps = windowBytes * 8.0 / rttSec / 1e6;
        f.lossLimitMbps = lossPct > 0 ? 1.22 * mss * 8.0 / (rttSec * Math.sqrt(lossPct / 100.0)) / 1e6
                                      : Double.POSITIVE_INFINITY;
        f.cpuLimitMbps = cpuNsPerSegment > 0 ? mss * 8.0 / cpuNsPerSegment * 1000.0 : Double.POSITIVE_INFINITY;

        f.goodputMbps = f.linkLimitMbps;
        f.limiter = "link rate";
        if (f.windowLimitMbps < f.goodputMbps) { f.goodputMbps = f.windowLimitMbps; f.limiter = "TCP window / RTT"; }
        if (f.lossLimitMbps < f.goodputMbps) { f.goodputMbps = f.lossLimitMbps; f.limiter = "packet loss (Mathis)"; }
        if (f.cpuLimitMbps < f.goodputMbps) { f.goodputMbps = f.cpuLimitMbps; f.limiter = "translator/tunnel CPU"; }
        f.efficiencyPct = 100.0 * f.goodputMbps / linkMbps;

        f.connectMs = f.rttMs;   // SYN -> SYN/ACK

        // Slow start: cwnd 10 MSS, doubling every RTT until it reaches the bandwidth-delay product.
        double bytes = transferMb * 1e6;
        double bdp = Math.min(windowBytes, f.goodputMbps * 1e6 / 8.0 * rttSec);
        double cwnd = 10.0 * mss;
        double sent = 0;
        double t = f.connectMs / 1000.0;
        while (cwnd < bdp && sent < bytes) {
            sent += cwnd;
            cwnd *= 2;
            t += rttSec;
        }
        if (sent < bytes) t += (bytes - sent) * 8.0 / (f.goodputMbps * 1e6);
        f.transferSec = t;
        return f;
    }
}
