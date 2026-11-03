package com.example.packetviewer.cn.net;

/**
 * RFC 6052 IPv4-embedded IPv6 addresses. The IPv4 address is spliced into the
 * prefix around the reserved "u" octet (bits 64-71), which must stay zero.
 *
 *   /32: v4 in bytes 4-7        /40: 5-7 then 9
 *   /48: 6-7 then 9-10          /56: 7 then 9-11
 *   /64: 9-12                   /96: 12-15
 */
public final class Nat64Prefix {

    public static final int[] LENGTHS = {32, 40, 48, 56, 64, 96};

    public final byte[] prefix;   // 16 bytes, bits past 'length' are zero
    public final int length;

    public Nat64Prefix(byte[] prefix16, int length) {
        if (prefix16 == null || prefix16.length != 16) throw new IllegalArgumentException("prefix must be 16 bytes");
        boolean ok = false;
        for (int l : LENGTHS) ok |= (l == length);
        if (!ok) throw new IllegalArgumentException("RFC 6052 prefix length must be 32/40/48/56/64/96");
        byte[] p = new byte[16];
        for (int i = 0; i < 16; i++) {
            int bitsLeft = length - i * 8;
            if (bitsLeft >= 8) p[i] = prefix16[i];
            else if (bitsLeft > 0) p[i] = (byte) (prefix16[i] & (0xFF << (8 - bitsLeft)));
        }
        this.prefix = p;
        this.length = length;
    }

    /** 64:ff9b::/96, the Well-Known Prefix. */
    public static Nat64Prefix wellKnown() {
        byte[] p = new byte[16];
        p[0] = 0x00;       // 0064:ff9b::
        p[1] = 0x64;
        p[2] = (byte) 0xFF;
        p[3] = (byte) 0x9B;
        return new Nat64Prefix(p, 96);
    }

    public boolean isWellKnown() {
        return length == 96 && java.util.Arrays.equals(prefix, wellKnown().prefix);
    }

    /** Byte indexes (in the IPv6 address) that carry the 4 IPv4 octets, in order. */
    private int[] slots() {
        switch (length) {
            case 32: return new int[]{4, 5, 6, 7};
            case 40: return new int[]{5, 6, 7, 9};
            case 48: return new int[]{6, 7, 9, 10};
            case 56: return new int[]{7, 9, 10, 11};
            case 64: return new int[]{9, 10, 11, 12};
            default: return new int[]{12, 13, 14, 15};
        }
    }

    public byte[] embed(byte[] v4) {
        byte[] a = prefix.clone();
        int[] s = slots();
        for (int i = 0; i < 4; i++) a[s[i]] = v4[i];
        return a;
    }

    /** True if the address lies inside this prefix and its u-octet is zero. */
    public boolean contains(byte[] v6) {
        int full = length / 8;
        for (int i = 0; i < full; i++) if (v6[i] != prefix[i]) return false;
        return v6[8] == 0;
    }

    public byte[] extract(byte[] v6) {
        int[] s = slots();
        byte[] v4 = new byte[4];
        for (int i = 0; i < 4; i++) v4[i] = v6[s[i]];
        return v4;
    }
}
