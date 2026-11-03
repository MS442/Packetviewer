package com.example.packetviewer.is2;

import com.example.packetviewer.cn.utils.TransitionUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * One-tap demo inputs for the Detector tab, covering the whole spectrum from
 * genuine to fake. The IPv4 packet headers are built with the same routines
 * as the CN section, so their checksums are real (and deliberately broken
 * in the forged example).
 *
 * Pure Java (no Android classes) so it can be unit-tested on the JVM.
 */
public final class DetectorExamples {

    private DetectorExamples() { }

    public static final class Example {
        public final String name;
        public final String ip;
        /** Raw header bytes as hex, or "" for none. */
        public final String hex;
        public final boolean lan;
        /** Prefix for the subnet step; "" = auto (/24 or /64). */
        public final String prefix;

        Example(String name, String ip, String hex, boolean lan, String prefix) {
            this.prefix = prefix;
            this.name = name;
            this.ip = ip;
            this.hex = hex;
            this.lan = lan;
        }
    }

    public static List<Example> all() {
        List<Example> list = new ArrayList<>();

        list.add(new Example("Normal public host + valid packet",
                "93.184.216.34",
                header("93.184.216.34", "8.8.4.4", 57, false), false, ""));

        list.add(new Example("Private address as an Internet source",
                "192.168.1.50",
                header("192.168.1.50", "93.184.216.34", 64, false), false, ""));

        list.add(new Example("Same private address on a LAN",
                "192.168.1.50",
                header("192.168.1.50", "192.168.1.1", 64, false), true, ""));

        list.add(new Example("Network address given to a host (/26)",
                "192.168.1.64",
                header("192.168.1.64", "192.168.1.1", 64, false), true, "26"));

        list.add(new Example("Broadcast address given to a host (/26)",
                "192.168.1.127",
                header("192.168.1.127", "192.168.1.1", 64, false), true, "26"));

        list.add(new Example("Hand-typed look (1.2.3.4)", "1.2.3.4", "", false, ""));

        list.add(new Example("Reserved Class E address", "240.12.34.56", "", false, ""));

        list.add(new Example("Forged header (bad checksum, src = dst, TTL 0)",
                "185.199.108.153",
                header("185.199.108.153", "185.199.108.153", 0, true), false, ""));

        list.add(new Example("IPv6 documentation range", "2001:db8:dead:beef::1", "", false, ""));

        list.add(new Example("Made-up IPv6 (1234:5678:...)",
                "1234:5678:9abc:def0:1234:5678:9abc:def0", "", false, ""));

        list.add(new Example("Normal public IPv6", "2606:4700:4700::1111", "", false, ""));

        return list;
    }

    /** Builds a 20-byte IPv4 header as uppercase hex; optionally corrupts the checksum. */
    private static String header(String src, String dst, int ttl, boolean corruptChecksum) {
        byte[] h = TransitionUtils.buildIPv4Header(
                TransitionUtils.parseIPv4(src), TransitionUtils.parseIPv4(dst),
                TransitionUtils.PROTO_TCP, ttl, 0, 60, 0x1C46, true);
        if (corruptChecksum) {
            h[11] = (byte) (h[11] ^ 0x5A);
            if ((h[10] == 0) && (h[11] == 0)) h[11] = 1; // keep it non-zero so it reads as "wrong", not "unset"
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < h.length; i++) {
            if (i > 0 && i % 4 == 0) sb.append(' ');
            sb.append(String.format(Locale.US, "%02X", h[i] & 0xFF));
        }
        return sb.toString();
    }
}
