package com.example.packetviewer.cn.models;

/**
 * POJO representing a parsed IPv4 header (RFC 791).
 */
public class IPv4HeaderModel {

    public int version = 4;
    public int ihl = 5;                 // In 32-bit words. 5 = 20 bytes (no options)
    public int tos = 0;                 // Type of Service / DSCP
    public int totalLength = 20;
    public int identification = 0;
    public boolean dfFlag = false;      // Don't Fragment
    public boolean mfFlag = false;      // More Fragments
    public int fragmentOffset = 0;
    public int ttl = 64;
    public int protocol = 6;            // 6 = TCP, 17 = UDP, 1 = ICMP
    public int checksum = 0;
    public String sourceAddress = "0.0.0.0";
    public String destinationAddress = "0.0.0.0";

    public int headerSizeBytes() {
        return ihl * 4;
    }

    public String protocolName() {
        switch (protocol) {
            case 1: return "ICMP";
            case 6: return "TCP";
            case 17: return "UDP";
            default: return "Unknown (" + protocol + ")";
        }
    }

    @Override
    public String toString() {
        return "=== IPv4 Header (RFC 791) ===\n" +
                "Version            : " + version + "\n" +
                "IHL                : " + ihl + " (" + headerSizeBytes() + " bytes)\n" +
                "Type of Service    : 0x" + Integer.toHexString(tos) + "\n" +
                "Total Length       : " + totalLength + " bytes\n" +
                "Identification     : 0x" + Integer.toHexString(identification).toUpperCase() + "\n" +
                "Flags              : DF=" + (dfFlag ? 1 : 0) + " MF=" + (mfFlag ? 1 : 0) + "\n" +
                "Fragment Offset    : " + fragmentOffset + "\n" +
                "TTL                : " + ttl + "\n" +
                "Protocol           : " + protocolName() + "\n" +
                "Header Checksum    : 0x" + Integer.toHexString(checksum).toUpperCase() + "\n" +
                "Source IP          : " + sourceAddress + "\n" +
                "Destination IP     : " + destinationAddress;
    }
}
