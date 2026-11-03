package com.example.packetviewer.cn;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RadioGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.example.packetviewer.R;

/**
 * Tab 1: Interactive Visual Viewer.
 *
 * Renders the RFC 791 (IPv4) or RFC 8200 (IPv6) header as a tappable
 * grid. Tapping any field updates the "Field Inspector" card at the
 * bottom with an explanation, bit range, and size - this is the CN
 * teaching/demo centerpiece of the app.
 */
public class ViewerFragment extends Fragment {

    private RadioGroup rgHeaderType;
    private View ipv4GridContainer;
    private View ipv6GridContainer;
    private TextView tvInspectorTitle;
    private TextView tvInspectorBody;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                              @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_viewer, container, false);

        rgHeaderType = view.findViewById(R.id.rgHeaderType);
        ipv4GridContainer = view.findViewById(R.id.layoutIPv4Grid);
        ipv6GridContainer = view.findViewById(R.id.layoutIPv6Grid);
        tvInspectorTitle = view.findViewById(R.id.tvInspectorTitle);
        tvInspectorBody = view.findViewById(R.id.tvInspectorBody);

        rgHeaderType.setOnCheckedChangeListener((group, checkedId) -> {
            boolean showIPv4 = checkedId == R.id.rbIPv4;
            ipv4GridContainer.setVisibility(showIPv4 ? View.VISIBLE : View.GONE);
            ipv6GridContainer.setVisibility(showIPv4 ? View.GONE : View.VISIBLE);
            resetInspector();
        });

        setupIPv4CellListeners(view);
        setupIPv6CellListeners(view);

        return view;
    }

    private void resetInspector() {
        tvInspectorTitle.setText("Field Inspector: Tap any grid block");
        tvInspectorBody.setText("Tap fields like TTL, Checksum, or Flow Label to inspect their purpose, size, and bit position.");
    }

    private void showInspector(String title, String body) {
        tvInspectorTitle.setText(title);
        tvInspectorBody.setText(body);
    }

    // ---------------------------------------------------------------
    // IPv4 field tap targets (RFC 791)
    // ---------------------------------------------------------------
    private void setupIPv4CellListeners(View root) {
        bindCell(root, R.id.cellVersion, "Version - 4 bits",
                "Always 0100 (decimal 4) for an IPv4 packet. Tells the receiver how to interpret the rest of the header.");
        bindCell(root, R.id.cellIHL, "IHL (Internet Header Length) - 4 bits",
                "Header length measured in 32-bit words. Minimum value is 5, meaning 5 x 4 = 20 bytes. Values above 5 indicate Options are present.");
        bindCell(root, R.id.cellTOS, "Type of Service (ToS / DSCP) - 8 bits",
                "Used for QoS: signals precedence, delay, throughput and reliability requirements for routers along the path.");
        bindCell(root, R.id.cellTotalLength, "Total Length - 16 bits",
                "Entire packet size (header + payload) in bytes. Maximum representable value is 65,535 bytes.");
        bindCell(root, R.id.cellIdentification, "Identification - 16 bits",
                "A unique value assigned by the sender, used by the destination to group and reassemble fragments belonging to the same original packet.");
        bindCell(root, R.id.cellFlags, "Flags - 3 bits",
                "Bit 0 reserved (must be 0). Bit 1 = DF (Don't Fragment). Bit 2 = MF (More Fragments, set on all fragments except the last).");
        bindCell(root, R.id.cellFragOffset, "Fragment Offset - 13 bits",
                "Indicates where this fragment belongs in the original packet, measured in units of 8 bytes.");
        bindCell(root, R.id.cellTTL, "Time To Live (TTL) - 8 bits",
                "Decremented by 1 at every router hop. When it reaches 0 the packet is discarded - this prevents infinite routing loops.");
        bindCell(root, R.id.cellProtocol, "Protocol - 8 bits",
                "Identifies the Layer 4 payload protocol. Common values: 1 = ICMP, 6 = TCP, 17 = UDP.");
        bindCell(root, R.id.cellChecksum, "Header Checksum - 16 bits",
                "One's Complement checksum computed strictly over the header bytes, used to detect header corruption in transit. Recomputed at every hop since TTL changes.");
        bindCell(root, R.id.cellSrcIP, "Source Address - 32 bits",
                "The sender's IPv4 address, written in dotted-decimal notation (e.g. 192.168.1.100).");
        bindCell(root, R.id.cellDstIP, "Destination Address - 32 bits",
                "The recipient's IPv4 address, written in dotted-decimal notation.");
    }

    // ---------------------------------------------------------------
    // IPv6 field tap targets (RFC 8200)
    // ---------------------------------------------------------------
    private void setupIPv6CellListeners(View root) {
        bindCell(root, R.id.cellVersion6, "Version - 4 bits",
                "Always 0110 (decimal 6) for an IPv6 packet.");
        bindCell(root, R.id.cellTrafficClass, "Traffic Class - 8 bits",
                "Equivalent to IPv4's ToS field - used for DiffServ / QoS marking.");
        bindCell(root, R.id.cellFlowLabel, "Flow Label - 20 bits",
                "Optionally used by a source to label sequences of packets that should be treated the same way by routers (e.g. same QoS path), enabling flow-based load balancing.");
        bindCell(root, R.id.cellPayloadLen, "Payload Length - 16 bits",
                "Size of the payload only (everything AFTER the fixed 40-byte header), unlike IPv4's Total Length which includes the header.");
        bindCell(root, R.id.cellNextHeader, "Next Header - 8 bits",
                "Replaces IPv4's Protocol field, but also chains Extension Headers (e.g. Routing, Fragment, IPSec/ESP) before finally pointing to the Layer 4 protocol.");
        bindCell(root, R.id.cellHopLimit, "Hop Limit - 8 bits",
                "Functionally identical to IPv4 TTL, renamed to accurately describe that it counts router hops rather than seconds.");
        bindCell(root, R.id.cellSrcIP6, "Source Address - 128 bits",
                "16-byte address written as 8 groups of hex separated by colons, e.g. 2001:db8:85a3::8a2e:370:7334.");
        bindCell(root, R.id.cellDstIP6, "Destination Address - 128 bits",
                "16-byte destination address. IPv6's massive address space (2^128) solves IPv4 exhaustion.");
    }

    private void bindCell(View root, int viewId, String title, String explanation) {
        View cell = root.findViewById(viewId);
        if (cell != null) {
            cell.setOnClickListener(v -> showInspector(title, explanation));
        }
    }
}
