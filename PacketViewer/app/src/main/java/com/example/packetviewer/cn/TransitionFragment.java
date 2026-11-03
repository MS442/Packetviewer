package com.example.packetviewer.cn;

import android.os.Bundle;
import android.text.InputType;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.example.packetviewer.R;
import com.example.packetviewer.cn.net.Benchmark;
import com.example.packetviewer.cn.net.Scenario;
import com.example.packetviewer.cn.net.TransitionDemo;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * CN, tab 3: IPv6 transition mechanisms.
 *
 * Every field is an input; the report is computed from them by the engine in
 * cn/net (real packet translation / encapsulation, checksum verification) with
 * per-packet costs measured on this device by cn/net/Benchmark. The benchmark
 * runs on a background thread so the UI stays responsive.
 */
public class TransitionFragment extends Fragment {

    private final Map<String, TextInputEditText> fields = new LinkedHashMap<>();
    private Spinner spMode;
    private CheckBox cbBlackhole;
    private Button btnRun;
    private ProgressBar progress;
    private TextView tvOutput;

    private volatile boolean running;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                              @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_transition, container, false);
        spMode = view.findViewById(R.id.spTransitionMode);
        cbBlackhole = view.findViewById(R.id.cbV6Blackholed);
        btnRun = view.findViewById(R.id.btnRunTransition);
        progress = view.findViewById(R.id.pbTransition);
        tvOutput = view.findViewById(R.id.tvTransitionOutput);

        spMode.setAdapter(new ArrayAdapter<>(requireContext(),
                android.R.layout.simple_spinner_dropdown_item, TransitionDemo.MODE_NAMES));
        buildForm((LinearLayout) view.findViewById(R.id.formContainer));
        btnRun.setOnClickListener(v -> run());
        return view;
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        fields.clear();
        spMode = null;
        cbBlackhole = null;
        btnRun = null;
        progress = null;
        tvOutput = null;
    }

    /** Adds one labelled input per Scenario value, pre-filled with the Scenario defaults. */
    private void buildForm(LinearLayout form) {
        Scenario d = new Scenario();
        heading(form, "Addresses");
        field(form, "clientV6", "Client IPv6 (IPv6-only host)", d.clientV6, false);
        field(form, "serverV4", "Server IPv4 (global address for the 64:ff9b::/96 prefix)", d.serverV4, false);
        field(form, "serverV6", "Server IPv6 (AAAA / 6in4 peer)", d.serverV6, false);
        field(form, "poolV4", "NAT64 pool IPv4 (translator address)", d.poolV4, false);
        field(form, "prefix", "NAT64 prefix", d.nat64Prefix, false);
        field(form, "prefixLen", "NAT64 prefix length (32/40/48/56/64/96)", String.valueOf(d.nat64PrefixLen), true);
        field(form, "tunLocal", "6in4 tunnel local IPv4", d.tunnelLocalV4, false);
        field(form, "tunRemote", "6in4 tunnel remote IPv4", d.tunnelRemoteV4, false);
        field(form, "hostV4", "DS-Lite host IPv4 (behind the B4)", d.hostV4, false);
        field(form, "b4", "DS-Lite B4 IPv6", d.b4V6, false);
        field(form, "aftr", "DS-Lite AFTR IPv6", d.aftrV6, false);
        heading(form, "Path");
        field(form, "rtt4", "IPv4 path RTT (ms)", fmt(d.rtt4Ms), true);
        field(form, "rtt6", "IPv6 path RTT (ms)", fmt(d.rtt6Ms), true);
        field(form, "detour", "Extra RTT to reach translator / tunnel end (ms)", fmt(d.detourMs), true);
        field(form, "link", "Bottleneck link rate (Mbit/s)", fmt(d.linkMbps), true);
        field(form, "loss", "Packet loss (%)", fmt(d.lossPct), true);
        field(form, "mtu", "Link MTU (bytes)", String.valueOf(d.mtu), true);
        field(form, "window", "TCP window (KB)", String.valueOf(d.windowKb), true);
        field(form, "size", "Transfer size (MB)", fmt(d.transferMb), true);
    }

    private void heading(LinearLayout form, String text) {
        TextView t = new TextView(requireContext());
        t.setText(text);
        t.setTextSize(13);
        t.setTypeface(t.getTypeface(), android.graphics.Typeface.BOLD);
        t.setTextColor(requireContext().getColor(R.color.colorPrimary));
        t.setPadding(0, 16, 0, 0);
        form.addView(t);
    }

    private void field(LinearLayout form, String key, String hint, String value, boolean numeric) {
        TextInputLayout layout = new TextInputLayout(requireContext());
        layout.setHint(hint);
        TextInputEditText edit = new TextInputEditText(layout.getContext());
        edit.setSingleLine(true);
        edit.setInputType(numeric ? InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_FLAG_DECIMAL
                                  : InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        edit.setText(value);
        layout.addView(edit, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = 8;
        form.addView(layout, lp);
        fields.put(key, edit);
    }

    private static String fmt(double d) {
        return d == Math.rint(d) ? String.valueOf((long) d) : String.valueOf(d);
    }

    private String text(String key) {
        return fields.get(key).getText().toString().trim();
    }

    private double number(String key) {
        try {
            return Double.parseDouble(text(key));
        } catch (NumberFormatException e) {
            fields.get(key).setError("Enter a number");
            throw e;
        }
    }

    private Scenario readScenario() {
        Scenario s = new Scenario();
        s.clientV6 = text("clientV6");
        s.serverV4 = text("serverV4");
        s.serverV6 = text("serverV6");
        s.poolV4 = text("poolV4");
        s.nat64Prefix = text("prefix");
        s.nat64PrefixLen = (int) number("prefixLen");
        s.tunnelLocalV4 = text("tunLocal");
        s.tunnelRemoteV4 = text("tunRemote");
        s.hostV4 = text("hostV4");
        s.b4V6 = text("b4");
        s.aftrV6 = text("aftr");
        s.rtt4Ms = number("rtt4");
        s.rtt6Ms = number("rtt6");
        s.detourMs = number("detour");
        s.linkMbps = number("link");
        s.lossPct = number("loss");
        s.mtu = (int) number("mtu");
        s.windowKb = (int) number("window");
        s.transferMb = number("size");
        s.v6Blackholed = cbBlackhole.isChecked();
        return s;
    }

    private void run() {
        if (running) return;
        final Scenario s;
        try {
            s = readScenario();
        } catch (NumberFormatException e) {
            return; // the offending field already shows its error
        }
        String problem = s.validate();
        if (problem != null) {
            tvOutput.setText("Input error: " + problem);
            return;
        }
        final int mode = spMode.getSelectedItemPosition();
        running = true;
        btnRun.setEnabled(false);
        progress.setVisibility(View.VISIBLE);
        tvOutput.setText("Measuring per-packet processing time on this device...");

        new Thread(() -> {
            String report;
            try {
                Benchmark.Costs costs = Benchmark.run(512, 1500, 11);
                report = TransitionDemo.run(s, mode, costs);
            } catch (RuntimeException e) {
                report = "Run failed: " + e;
            }
            final String result = report;
            if (getActivity() != null) {
                getActivity().runOnUiThread(() -> {
                    running = false;
                    if (tvOutput == null) return; // view destroyed meanwhile
                    tvOutput.setText(result);
                    btnRun.setEnabled(true);
                    progress.setVisibility(View.GONE);
                });
            } else {
                running = false;
            }
        }, "transition-bench").start();
    }
}
