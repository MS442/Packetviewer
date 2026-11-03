package com.example.packetviewer.cn.net;

/**
 * Internet checksum (RFC 1071) plus the incremental update of RFC 1624.
 * Every translator/tunnel step in this package that changes a header
 * recomputes or incrementally updates a real checksum with these helpers.
 */
public final class Checksum {

    private Checksum() { }

    /** Adds the 16-bit big-endian words of b[off, off+len) to sum (odd tail byte padded with 0). */
    public static long add(long sum, byte[] b, int off, int len) {
        int i = off;
        int end = off + len;
        while (i + 1 < end) {
            sum += ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
            i += 2;
        }
        if (i < end) sum += (b[i] & 0xFF) << 8;
        return sum;
    }

    /** Folds carries and returns the one's complement (the value that goes in the header). */
    public static int finish(long sum) {
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum & 0xFFFF);
    }

    /** Checksum of a plain byte range (IPv4 header, ICMPv4). */
    public static int of(byte[] b, int off, int len) {
        return finish(add(0, b, off, len));
    }

    /** IPv4 pseudo-header partial sum (src, dst, 0|proto, L4 length). */
    public static long pseudoV4(byte[] src, byte[] dst, int proto, int l4Len) {
        long s = add(0, src, 0, 4);
        s = add(s, dst, 0, 4);
        return s + proto + l4Len;
    }

    /** IPv6 pseudo-header partial sum (src, dst, L4 length, next header). */
    public static long pseudoV6(byte[] src, byte[] dst, int nextHeader, int l4Len) {
        long s = add(0, src, 0, 16);
        s = add(s, dst, 0, 16);
        return s + l4Len + nextHeader;
    }

    /**
     * RFC 1624 eqn. 3: HC' = ~(~HC + ~m + m'). Replaces one 16-bit word m by m'
     * in a checksummed block without re-reading the block.
     */
    public static int update(int oldChecksum, int oldWord, int newWord) {
        long sum = (~oldChecksum & 0xFFFF) + (~oldWord & 0xFFFF) + (newWord & 0xFFFF);
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum & 0xFFFF);
    }

    /** Applies update() for every 16-bit word of an address/field that changed from oldB to newB. */
    public static int updateBytes(int checksum, byte[] oldB, int oldOff, int oldLen,
                                  byte[] newB, int newOff, int newLen) {
        // Remove the old words, then add the new words (works when the lengths differ,
        // e.g. 16-byte IPv6 address -> 4-byte IPv4 address).
        long sum = ~checksum & 0xFFFF;
        for (int i = 0; i < oldLen; i += 2) {
            int w = ((oldB[oldOff + i] & 0xFF) << 8) | (i + 1 < oldLen ? (oldB[oldOff + i + 1] & 0xFF) : 0);
            sum += (~w) & 0xFFFF;
        }
        for (int i = 0; i < newLen; i += 2) {
            int w = ((newB[newOff + i] & 0xFF) << 8) | (i + 1 < newLen ? (newB[newOff + i + 1] & 0xFF) : 0);
            sum += w;
        }
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum & 0xFFFF);
    }
}
