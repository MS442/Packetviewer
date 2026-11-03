package com.example.packetviewer.cn;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.example.packetviewer.R;
import com.example.packetviewer.cn.utils.SubnetCalculator;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * CN, tab 2: Subnet Calculator. Calculate / split / VLSM for IPv4 and IPv6.
 * All the maths is in utils/SubnetCalculator; this class only wires up views.
 * The IS2 detector calls the same calculator as its step 0.
 */
public class SubnetFragment extends Fragment {

    private static final int MAX_LISTED = 64;

    private EditText etInput, etSplit, etVlsm;
    private TextView tvOutput;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                              @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_subnet, container, false);
        etInput = view.findViewById(R.id.etSubnetInput);
        etSplit = view.findViewById(R.id.etSplitPrefix);
        etVlsm = view.findViewById(R.id.etVlsm);
        tvOutput = view.findViewById(R.id.tvSubnetOutput);

        view.findViewById(R.id.btnSubnetCalc).setOnClickListener(v -> calculate());
        view.findViewById(R.id.btnSplit).setOnClickListener(v -> split());
        view.findViewById(R.id.btnVlsm).setOnClickListener(v -> vlsm());
        return view;
    }

    private SubnetCalculator.Parsed parseInput() {
        String text = etInput.getText().toString();
        SubnetCalculator.Parsed p = SubnetCalculator.parseWithAddress(text);
        if (p == null) {
            etInput.setError(SubnetCalculator.error(text));
            return null;
        }
        etInput.setError(null);
        return p;
    }

    private void calculate() {
        SubnetCalculator.Parsed p = parseInput();
        if (p == null) return;
        SubnetCalculator.Subnet s = p.subnet;
        StringBuilder sb = new StringBuilder(s.describe());
        sb.append("\nThe address you typed is ").append(describePosition(s.position(p.address)))
          .append(".\n");
        tvOutput.setText(sb.toString());
    }

    private static String describePosition(SubnetCalculator.Position pos) {
        switch (pos) {
            case NETWORK_ADDRESS: return "the network address (not usable by a host)";
            case BROADCAST_ADDRESS: return "the broadcast address (not usable by a host)";
            case ROUTER_ANYCAST: return "the subnet-router anycast address";
            default: return "a usable host address";
        }
    }

    private void split() {
        SubnetCalculator.Parsed p = parseInput();
        if (p == null) return;
        int n;
        try {
            n = Integer.parseInt(etSplit.getText().toString().trim());
        } catch (NumberFormatException e) {
            etSplit.setError("Enter a prefix length");
            return;
        }
        List<SubnetCalculator.Subnet> parts = SubnetCalculator.split(p.subnet, n, MAX_LISTED);
        if (parts == null) {
            etSplit.setError("Must be longer than /" + p.subnet.prefixLen + " and at most /" + p.subnet.bits);
            return;
        }
        etSplit.setError(null);
        StringBuilder sb = new StringBuilder();
        sb.append(p.subnet.cidr()).append(" split into /").append(n).append(": ")
          .append(SubnetCalculator.splitCount(p.subnet, n)).append(" subnets");
        if (parts.size() == MAX_LISTED) sb.append(" (first ").append(MAX_LISTED).append(" shown)");
        sb.append("\n\n");
        for (int i = 0; i < parts.size(); i++) {
            SubnetCalculator.Subnet s = parts.get(i);
            sb.append(String.format(Locale.US, "%2d. %s   hosts %s - %s%n", i + 1, s.cidr(),
                    s.text(s.firstHost()), s.text(s.lastHost())));
        }
        tvOutput.setText(sb.toString());
    }

    private void vlsm() {
        SubnetCalculator.Parsed p = parseInput();
        if (p == null) return;
        List<String> labels = new ArrayList<>();
        List<Integer> hosts = new ArrayList<>();
        String[] lines = etVlsm.getText().toString().split("\\n");
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            String[] parts = t.split("\\s+");
            try {
                int h = Integer.parseInt(parts[parts.length - 1]);
                if (h < 1) throw new NumberFormatException();
                hosts.add(h);
                labels.add(parts.length > 1 ? t.substring(0, t.lastIndexOf(parts[parts.length - 1])).trim() : "LAN" + (labels.size() + 1));
            } catch (NumberFormatException e) {
                etVlsm.setError("Each line is 'name hosts' with hosts >= 1, got: " + t);
                return;
            }
        }
        if (hosts.isEmpty()) {
            etVlsm.setError("Add at least one line like: Sales 100");
            return;
        }
        etVlsm.setError(null);
        String[] failure = new String[1];
        List<SubnetCalculator.Allocation> result = SubnetCalculator.vlsm(p.subnet, labels, hosts, failure);
        tvOutput.setText(result == null ? "VLSM failed: " + failure[0]
                                        : SubnetCalculator.vlsmReport(p.subnet, result));
    }
}
