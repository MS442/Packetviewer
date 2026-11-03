package com.example.packetviewer.is2.analysis;

import com.example.packetviewer.cn.utils.TransitionUtils;
import com.example.packetviewer.cn.utils.TransitionUtils.V6Kind;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * FIS input 3: "Header". Cross-checks the optional raw packet bytes against
 * the address the user entered and against the header's own rules. A forged
 * or hand-built packet usually breaks at least one of them.
 *
 * Score = sum of penalties, capped at 100:
 *
 *   IPv4: bad checksum 45, source == destination 45, illegal source address 50,
 *         address entered matches neither end 35, TTL 0 30, DF+MF both set 25,
 *         total length smaller than header 40, IHL below 5 45,
 *         reserved flag bit 15, checksum left at 0 10
 *   IPv6: source == destination 45, multicast source 50, loopback source 45,
 *         unspecified source 25, address entered matches neither end 35,
 *         hop limit 0 30
 *   both: version field disagrees with the address family 70
 *
 * If no usable packet is supplied the check is skipped and the input is 0
 * (the report says so), so absence of a packet never counts against an address.
 *
 * Pure Java (no Android classes) so it can be unit-tested on the JVM.
 */
public final class HeaderForensics {

    private HeaderForensics() { }

    public static final class Result {
        /** False when no usable packet was supplied (check skipped). */
        public final boolean checked;
        public final double score;
        public final List<String> reasons;

        Result(boolean checked, double score, List<String> reasons) {
            this.checked = checked;
            this.score = score;
            this.reasons = reasons;
        }
    }

    /**
     * @param hex         raw header bytes as hex text (spaces, colons and 0x are ignored); may be empty
     * @param entered     the address the user typed, as 4 (IPv4) or 16 (IPv6) bytes
     * @param enteredIsV6 true when the address entered is IPv6
     */
    public static Result analyze(String hex, byte[] entered, boolean enteredIsV6) {
        List<String> why = new ArrayList<>();

        String clean = (hex == null) ? "" : hex.replaceAll("(?i)0x", "").replaceAll("[^0-9a-fA-F]", "");
        if (clean.isEmpty()) {
            why.add("no packet supplied: header check skipped (counts as 0)");
            return new Result(false, 0, why);
        }
        if (clean.length() % 2 != 0) {
            why.add("odd number of hex digits: header check skipped (counts as 0)");
            return new Result(false, 0, why);
        }

        byte[] b = new byte[clean.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) ((Character.digit(clean.charAt(2 * i), 16) << 4)
                    + Character.digit(clean.charAt(2 * i + 1), 16));
        }

        int version = (b[0] >>> 4) & 0x0F;
        int expected = enteredIsV6 ? 6 : 4;
        if (version != expected) {
            why.add("version field says IPv" + version + " but the address entered is IPv" + expected);
            return new Result(true, 70, why);
        }
        return enteredIsV6 ? analyzeV6(b, entered, why) : analyzeV4(b, entered, why);
    }

    // ------------------------------------------------------------------

    private static Result analyzeV4(byte[] b, byte[] entered, List<String> why) {
        if (b.length < 20) {
            why.add("only " + b.length + " bytes supplied (an IPv4 header needs 20): header check skipped (counts as 0)");
            return new Result(false, 0, why);
        }

        double score = 0;
        int ihl = b[0] & 0x0F;
        int headerLen = ihl * 4;
        int totalLen = ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
        int flagsAndOffset = ((b[6] & 0xFF) << 8) | (b[7] & 0xFF);
        int ttl = b[8] & 0xFF;
        int stored = ((b[10] & 0xFF) << 8) | (b[11] & 0xFF);
        byte[] src = Arrays.copyOfRange(b, 12, 16);
        byte[] dst = Arrays.copyOfRange(b, 16, 20);

        if (ihl < 5) {
            score += 45;
            why.add("IHL is " + ihl + " (the minimum legal value is 5)");
        } else if (b.length < headerLen) {
            why.add("only " + b.length + " of " + headerLen + " header bytes supplied: checksum not verified");
        } else if (stored == 0) {
            score += 10;
            why.add("checksum field is 0 (not filled in; can be checksum offload)");
        } else if (!checksumVerifies(b, headerLen)) {
            score += 45;
            why.add(String.format(Locale.US,
                    "header checksum 0x%04X does not verify: header altered or forged", stored));
        }

        if (totalLen < Math.max(headerLen, 20)) {
            score += 40;
            why.add("total length " + totalLen + " is smaller than the header itself");
        }
        if (ttl == 0) {
            score += 30;
            why.add("TTL is 0: such a packet is dropped before it can be forwarded");
        }
        if ((flagsAndOffset & 0x8000) != 0) {
            score += 15;
            why.add("reserved flag bit is set (must be 0)");
        }
        if ((flagsAndOffset & 0x4000) != 0 && (flagsAndOffset & 0x2000) != 0) {
            score += 25;
            why.add("DF and MF are both set (a packet that must not be fragmented claims more fragments)");
        }
        if (Arrays.equals(src, dst)) {
            score += 45;
            why.add("source equals destination (signature of a LAND attack)");
        }
        RangeClassifier.Result srcRange = RangeClassifier.classifyV4(src, RangeClassifier.Scenario.INTERNET);
        if (srcRange.invalidAsSource()) {
            score += 50;
            why.add("source " + TransitionUtils.formatIPv4(src) + " is in a "
                    + srcRange.kind + " block, which can never be a real packet source");
        }
        if (!Arrays.equals(entered, src) && !Arrays.equals(entered, dst)) {
            score += 35;
            why.add("address entered matches neither the source (" + TransitionUtils.formatIPv4(src)
                    + ") nor the destination (" + TransitionUtils.formatIPv4(dst) + ")");
        }

        if (score == 0) {
            why.add("version, length, TTL, flags, checksum, source and entered address are all consistent");
        }
        return new Result(true, Math.min(100, score), why);
    }

    private static Result analyzeV6(byte[] b, byte[] entered, List<String> why) {
        if (b.length < 40) {
            why.add("only " + b.length + " bytes supplied (an IPv6 header needs 40): header check skipped (counts as 0)");
            return new Result(false, 0, why);
        }

        double score = 0;
        int hopLimit = b[7] & 0xFF;
        byte[] src = Arrays.copyOfRange(b, 8, 24);
        byte[] dst = Arrays.copyOfRange(b, 24, 40);

        if (hopLimit == 0) {
            score += 30;
            why.add("hop limit is 0: such a packet is dropped before it can be forwarded");
        }
        if (Arrays.equals(src, dst)) {
            score += 45;
            why.add("source equals destination (signature of a LAND attack)");
        }
        V6Kind srcKind = TransitionUtils.classifyV6(src);
        if (srcKind == V6Kind.MULTICAST) {
            score += 50;
            why.add("source is a multicast address, which can never be a real packet source");
        } else if (srcKind == V6Kind.LOOPBACK && !Arrays.equals(src, dst)) {
            score += 45;
            why.add("source is ::1 (loopback) in a packet addressed elsewhere");
        } else if (srcKind == V6Kind.UNSPECIFIED) {
            score += 25;
            why.add("source is :: (unspecified), only legitimate during address start-up");
        }
        if (!Arrays.equals(entered, src) && !Arrays.equals(entered, dst)) {
            score += 35;
            why.add("address entered matches neither the source nor the destination in the header");
        }

        if (score == 0) {
            why.add("version, hop limit, source and entered address are all consistent");
        }
        return new Result(true, Math.min(100, score), why);
    }

    /** One's-complement sum over the whole header (checksum field included) must equal 0xFFFF. */
    private static boolean checksumVerifies(byte[] b, int headerLen) {
        long sum = 0;
        for (int i = 0; i < headerLen; i += 2) {
            sum += ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
        }
        while ((sum >>> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >>> 16);
        }
        return sum == 0xFFFF;
    }
}
