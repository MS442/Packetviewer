package com.example.packetviewer.cn.models;

/**
 * POJO representing a parsed IPv6 header (RFC 8200).
 * Base header is ALWAYS a fixed 40 bytes.
 */
public class IPv6HeaderModel {

    public int version = 6;
    public int trafficClass = 0;
    public int flowLabel = 0;
    public int payloadLength = 0;
    public int nextHeader = 6;      // 6 = TCP, 17 = UDP, 58 = ICMPv6
    public int hopLimit = 64;
    public String sourceAddress = "::";
    public String destinationAddress = "::";

    public static final int HEADER_SIZE_BYTES = 40; // fixed, no IHL field needed

    public String nextHeaderName() {
        switch (nextHeader) {
            case 6: return "TCP";
            case 17: return "UDP";
            case 58: return "ICMPv6";
            default: return "Unknown (" + nextHeader + ")";
        }
    }

    @Override
    public String toString() {
        return "=== IPv6 Header (RFC 8200) ===\n" +
                "Version            : " + version + "\n" +
                "Traffic Class      : 0x" + Integer.toHexString(trafficClass) + "\n" +
                "Flow Label         : 0x" + Integer.toHexString(flowLabel) + "\n" +
                "Payload Length     : " + payloadLength + " bytes\n" +
                "Next Header        : " + nextHeaderName() + "\n" +
                "Hop Limit          : " + hopLimit + "\n" +
                "Header Size        : " + HEADER_SIZE_BYTES + " bytes (fixed)\n" +
                "Source IP          : " + sourceAddress + "\n" +
                "Destination IP     : " + destinationAddress;
    }
}
