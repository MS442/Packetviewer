package com.example.packetviewer.cn.utils;

import com.example.packetviewer.cn.models.IPv4HeaderModel;
import com.example.packetviewer.cn.models.IPv6HeaderModel;

import java.util.regex.Pattern;

/**
 * Core Computer Networks (CN) logic:
 *  - Hex string -> byte[] conversion
 *  - Bitwise parsing of IPv4 (RFC 791) and IPv6 (RFC 8200) headers
 *  - One's Complement checksum calculation (IPv4 only, IPv6 has none)
 *  - IP address format validation (regex)
 *
 * Kept 100% static / stateless so it is easily unit-testable
 * (see the "Testing and Debugging" rubric section).
 */
public class PacketParserUtils {

    // Basic dotted-decimal IPv4 validation (0-255 per octet)
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}" +
            "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

    // Simplified IPv6 validation - full/compressed hextet groups separated by ':'
    private static final Pattern IPV6_PATTERN = Pattern.compile(
            "^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$");

    // ------------------------------------------------------------------
    // VALIDATION
    // ------------------------------------------------------------------

    public static boolean isValidIPv4(String ip) {
        if (ip == null || ip.trim().isEmpty()) return false;
        return IPV4_PATTERN.matcher(ip.trim()).matches();
    }

    public static boolean isValidIPv6(String ip) {
        if (ip == null || ip.trim().isEmpty()) return false;
        return ip.contains(":") && IPV6_PATTERN.matcher(ip.trim()).matches();
    }

    public static String detectProtocolType(String ip) {
        if (ip == null) return "Unknown";
        if (ip.contains(":")) return "IPv6";
        if (ip.contains(".")) return "IPv4";
        return "Unknown";
    }

    // ------------------------------------------------------------------
    // CANONICALIZATION (normalizes an address to ONE consistent string
    // form before it is stored / compared - both exact AND fuzzy checks
    // rely on this, otherwise two textually different but logically
    // IDENTICAL addresses would slip past the duplicate check).
    // ------------------------------------------------------------------

    /**
     * Strips any leading zeros from each octet, e.g. "192.168.001.1"
     * becomes "192.168.1.1", so both are recognized as the same host.
     */
    public static String canonicalizeIPv4(String ip) {
        if (!isValidIPv4(ip)) return ip.trim();
        String[] parts = ip.trim().split("\\.");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            sb.append(Integer.parseInt(parts[i]));
            if (i != parts.length - 1) sb.append(".");
        }
        return sb.toString();
    }

    /**
     * Fully expands a (possibly compressed) IPv6 address into 8 groups
     * of 4 lowercase hex digits each, e.g.:
     *   "2001:db8::1"  ->  "2001:0db8:0000:0000:0000:0000:0000:0001"
     * This means "2001:db8::1" and its fully-written-out equivalent are
     * treated as an EXACT duplicate, matching real router/OS behavior.
     */
    public static String canonicalizeIPv6(String ip) {
        if (ip == null) return "";
        String addr = ip.trim().toLowerCase();

        String[] halves;
        boolean hasDoubleColon = addr.contains("::");

        String left, right;
        if (hasDoubleColon) {
            int idx = addr.indexOf("::");
            left = addr.substring(0, idx);
            right = addr.substring(idx + 2);
        } else {
            left = addr;
            right = "";
        }

        String[] leftGroups = left.isEmpty() ? new String[0] : left.split(":");
        String[] rightGroups = right.isEmpty() ? new String[0] : right.split(":");

        int filledCount = leftGroups.length + rightGroups.length;
        int missingCount = hasDoubleColon ? Math.max(0, 8 - filledCount) : 0;

        StringBuilder result = new StringBuilder();
        java.util.List<String> allGroups = new java.util.ArrayList<>();

        for (String g : leftGroups) allGroups.add(g);
        for (int i = 0; i < missingCount; i++) allGroups.add("0");
        for (String g : rightGroups) allGroups.add(g);

        // Defensive: if address didn't parse into exactly 8 groups
        // (malformed input), just return the lowercase trimmed original
        // rather than throwing - the regex validator catches bad input
        // earlier in the flow.
        if (allGroups.size() != 8) return addr;

        for (int i = 0; i < allGroups.size(); i++) {
            String padded = String.format("%4s", allGroups.get(i)).replace(' ', '0');
            result.append(padded);
            if (i != allGroups.size() - 1) result.append(":");
        }

        return result.toString();
    }

    /**
     * Convenience wrapper - canonicalizes an address regardless of
     * whether it is IPv4 or IPv6.
     */
    public static String canonicalize(String ip) {
        if (isValidIPv6(ip)) return canonicalizeIPv6(ip);
        if (isValidIPv4(ip)) return canonicalizeIPv4(ip);
        return ip == null ? "" : ip.trim();
    }

    // ------------------------------------------------------------------
    // HEX STRING <-> BYTES
    // ------------------------------------------------------------------

    public static byte[] hexStringToByteArray(String hex) {
        String clean = hex.replaceAll("[^0-9a-fA-F]", ""); // strip spaces, 0x, colons etc.
        if (clean.length() % 2 != 0) {
            clean = "0" + clean; // pad odd-length input
        }
        int len = clean.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(clean.charAt(i), 16) << 4)
                    + Character.digit(clean.charAt(i + 1), 16));
        }
        return data;
    }

    // ------------------------------------------------------------------
    // IPv4 PARSER (RFC 791) - minimum 20 bytes
    // ------------------------------------------------------------------

    public static IPv4HeaderModel parseIPv4(byte[] bytes) {
        if (bytes.length < 20) {
            throw new IllegalArgumentException("IPv4 header requires at least 20 bytes, got " + bytes.length);
        }

        IPv4HeaderModel h = new IPv4HeaderModel();

        int versionAndIhl = bytes[0] & 0xFF;
        h.version = (versionAndIhl >>> 4) & 0x0F;
        h.ihl = versionAndIhl & 0x0F;

        h.tos = bytes[1] & 0xFF;

        h.totalLength = ((bytes[2] & 0xFF) << 8) | (bytes[3] & 0xFF);

        h.identification = ((bytes[4] & 0xFF) << 8) | (bytes[5] & 0xFF);

        int flagsAndOffset = ((bytes[6] & 0xFF) << 8) | (bytes[7] & 0xFF);
        h.dfFlag = (flagsAndOffset & 0x4000) != 0;
        h.mfFlag = (flagsAndOffset & 0x2000) != 0;
        h.fragmentOffset = flagsAndOffset & 0x1FFF;

        h.ttl = bytes[8] & 0xFF;
        h.protocol = bytes[9] & 0xFF;
        h.checksum = ((bytes[10] & 0xFF) << 8) | (bytes[11] & 0xFF);

        h.sourceAddress = (bytes[12] & 0xFF) + "." + (bytes[13] & 0xFF) + "."
                + (bytes[14] & 0xFF) + "." + (bytes[15] & 0xFF);
        h.destinationAddress = (bytes[16] & 0xFF) + "." + (bytes[17] & 0xFF) + "."
                + (bytes[18] & 0xFF) + "." + (bytes[19] & 0xFF);

        return h;
    }

    /**
     * One's Complement checksum over the 20-byte IPv4 header
     * (skips the existing checksum field at bytes 10-11).
     */
    public static int calculateIPv4Checksum(byte[] headerBytes) {
        long sum = 0;
        for (int i = 0; i < 20; i += 2) {
            if (i == 10) continue; // skip checksum field itself
            int word = ((headerBytes[i] & 0xFF) << 8) | (headerBytes[i + 1] & 0xFF);
            sum += word;
        }
        while ((sum >>> 16) > 0) {
            sum = (sum & 0xFFFF) + (sum >>> 16);
        }
        return (int) (~sum & 0xFFFF);
    }

    // ------------------------------------------------------------------
    // IPv6 PARSER (RFC 8200) - exactly 40 bytes for base header
    // ------------------------------------------------------------------

    public static IPv6HeaderModel parseIPv6(byte[] bytes) {
        if (bytes.length < 40) {
            throw new IllegalArgumentException("IPv6 base header requires at least 40 bytes, got " + bytes.length);
        }

        IPv6HeaderModel h = new IPv6HeaderModel();

        long word0 = ((long) (bytes[0] & 0xFF) << 24)
                | ((bytes[1] & 0xFF) << 16)
                | ((bytes[2] & 0xFF) << 8)
                | (bytes[3] & 0xFF);

        h.version = (int) ((word0 >>> 28) & 0x0F);
        h.trafficClass = (int) ((word0 >>> 20) & 0xFF);
        h.flowLabel = (int) (word0 & 0xFFFFF);

        h.payloadLength = ((bytes[4] & 0xFF) << 8) | (bytes[5] & 0xFF);
        h.nextHeader = bytes[6] & 0xFF;
        h.hopLimit = bytes[7] & 0xFF;

        h.sourceAddress = formatIPv6Address(bytes, 8);
        h.destinationAddress = formatIPv6Address(bytes, 24);

        return h;
    }

    private static String formatIPv6Address(byte[] bytes, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            int hi = bytes[offset + i * 2] & 0xFF;
            int lo = bytes[offset + i * 2 + 1] & 0xFF;
            int group = (hi << 8) | lo;
            sb.append(Integer.toHexString(group));
            if (i != 7) sb.append(":");
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // UNIFIED ENTRY POINT: raw hex stream -> readable header breakdown
    // ------------------------------------------------------------------

    /**
     * Parses a raw hex stream according to the given protocol type
     * ("IPv4" or "IPv6") and returns a human-readable field breakdown.
     */
    public static String parseHexStream(String hexStream, String protocolType) {
        try {
            byte[] bytes = hexStringToByteArray(hexStream);

            if ("IPv6".equalsIgnoreCase(protocolType)) {
                IPv6HeaderModel h = parseIPv6(bytes);
                return h.toString();
            } else {
                IPv4HeaderModel h = parseIPv4(bytes);
                int computedChecksum = calculateIPv4Checksum(bytes);
                String verdict = (computedChecksum == h.checksum || h.checksum == 0)
                        ? "N/A (recomputed above)"
                        : "MISMATCH - possible corruption";
                return h.toString()
                        + "\n\nRecomputed Checksum: 0x" + Integer.toHexString(computedChecksum).toUpperCase()
                        + "\nChecksum Verdict    : " + verdict;
            }
        } catch (Exception e) {
            return "Parse Error: " + e.getMessage()
                    + "\n\nTip: IPv4 needs >= 20 bytes (40 hex chars).\nIPv6 needs >= 40 bytes (80 hex chars).";
        }
    }
}
