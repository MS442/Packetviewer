package com.example.packetviewer.is2;

import android.app.AlertDialog;
import android.content.res.ColorStateList;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.example.packetviewer.R;
import com.example.packetviewer.is2.analysis.FakeIpAnalyzer;
import com.example.packetviewer.is2.analysis.RangeClassifier;
import com.example.packetviewer.is2.database.IPDatabaseHelper;
import com.example.packetviewer.is2.fuzzy.FakeIpFIS;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * IS2, tab 1: Fake-IP Detector.
 *
 * Flow:
 *   0. Subnetting: find the subnet + host position (prefix, mask or auto)
 *   1. Validate the address (strict IPv4 / IPv6 parser)
 *   2. SQLite per-subnet lookup: if it was analysed before in that subnet, show the stored
 *      verdict and let the user re-analyse (the result depends on the
 *      scenario and packet bytes) or cancel
 *   3. Run the Mamdani FIS (FakeIpAnalyzer) and store score + verdict
 *   4. Show the verdict, a score bar and the step-by-step fuzzy reasoning
 *
 * All the analysis lives in is2/analysis and is2/fuzzy; this fragment only
 * wires up the views.
 */
public class DetectorFragment extends Fragment {

    private EditText etIp;
    private EditText etHex;
    private EditText etPrefix;
    private RadioButton rbInternet;
    private RadioButton rbLan;
    private Spinner spExamples;
    private TextView tvVerdict;
    private TextView tvScore;
    private ProgressBar pbScore;
    private TextView tvOutput;

    private IPDatabaseHelper dbHelper;
    private final FakeIpAnalyzer analyzer = new FakeIpAnalyzer();
    private final List<DetectorExamples.Example> examples = DetectorExamples.all();

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                              @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_detector, container, false);

        etIp = view.findViewById(R.id.etDetectorIp);
        etHex = view.findViewById(R.id.etDetectorHex);
        etPrefix = view.findViewById(R.id.etDetectorPrefix);
        rbInternet = view.findViewById(R.id.rbInternet);
        rbLan = view.findViewById(R.id.rbLan);
        spExamples = view.findViewById(R.id.spExamples);
        tvVerdict = view.findViewById(R.id.tvVerdict);
        tvScore = view.findViewById(R.id.tvScore);
        pbScore = view.findViewById(R.id.pbScore);
        tvOutput = view.findViewById(R.id.tvDetectorOutput);
        Button btnAnalyze = view.findViewById(R.id.btnAnalyze);

        dbHelper = new IPDatabaseHelper(requireContext());

        // Example picker: item 0 is a prompt, the rest are DetectorExamples.
        List<String> names = new ArrayList<>();
        names.add("Load an example...");
        for (DetectorExamples.Example example : examples) {
            names.add(example.name);
        }
        ArrayAdapter<String> adapter = new ArrayAdapter<>(requireContext(),
                android.R.layout.simple_spinner_item, names);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spExamples.setAdapter(adapter);
        spExamples.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View v, int position, long id) {
                if (position == 0) return; // the prompt row
                DetectorExamples.Example example = examples.get(position - 1);
                etIp.setText(example.ip);
                etIp.setError(null);
                etHex.setText(example.hex);
                etPrefix.setText(example.prefix);
                (example.lan ? rbLan : rbInternet).setChecked(true);
                spExamples.setSelection(0); // back to the prompt so the same example can be picked again
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) { /* no-op */ }
        });

        btnAnalyze.setOnClickListener(v -> analyze());

        return view;
    }

    private void analyze() {
        String ip = etIp.getText().toString().trim();
        RangeClassifier.Scenario scenario = rbLan.isChecked()
                ? RangeClassifier.Scenario.LAN
                : RangeClassifier.Scenario.INTERNET;

        // STEP 0 + 1: subnetting and strict validation (also parses the packet bytes, if any)
        FakeIpAnalyzer.Analysis analysis;
        try {
            analysis = analyzer.analyze(ip, etHex.getText().toString(), scenario,
                    etPrefix.getText().toString());
        } catch (IllegalArgumentException e) {
            etPrefix.setError(e.getMessage());
            return;
        }
        etPrefix.setError(null);
        if (analysis == null) {
            etIp.setError("Enter a valid IPv4 (e.g. 192.168.1.50) or IPv6 (e.g. 2001:db8::1) address");
            return;
        }

        // STEP 2: duplicate check, scoped to the subnet found in step 0
        IPDatabaseHelper.HistoryEntry previous =
                dbHelper.findByIp(analysis.canonical, analysis.subnet.prefixLen());
        if (previous != null) {
            showAlreadyAnalysedDialog(previous, analysis);
            return;
        }

        // STEP 3 + 4: store and show
        commit(analysis);
    }

    private void commit(FakeIpAnalyzer.Analysis analysis) {
        boolean saved = dbHelper.saveResult(analysis.canonical, analysis.protocol,
                analysis.subnet.prefixLen(), analysis.subnet.network(),
                analysis.score, analysis.verdict);
        render(analysis);
        Toast.makeText(getContext(),
                saved ? "Result saved to history" : "Could not save to the database",
                Toast.LENGTH_SHORT).show();
    }

    private void showAlreadyAnalysedDialog(IPDatabaseHelper.HistoryEntry previous,
                                           FakeIpAnalyzer.Analysis fresh) {
        new AlertDialog.Builder(requireContext())
                .setTitle("Already analysed in this subnet")
                .setMessage(previous.ipAddress + " is already in the database"
                        + (previous.prefixLen >= 0 ? " for subnet " + previous.network + "/" + previous.prefixLen : "")
                        + ".\n\n"
                        + "Stored result: " + previous.verdictText() + "\n"
                        + "Analysed at: " + previous.testedAt + " (UTC)\n\n"
                        + "The score depends on the scenario and packet bytes you entered, "
                        + "so you can re-analyse it and update the stored result.")
                .setIcon(android.R.drawable.ic_dialog_info)
                .setPositiveButton("Re-analyse", (dialog, which) -> commit(fresh))
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void render(FakeIpAnalyzer.Analysis analysis) {
        int color = requireContext().getColor(colorFor(analysis.label));

        tvVerdict.setText(analysis.verdict);
        tvVerdict.setTextColor(color);
        tvScore.setText(String.format(Locale.US, "Suspicion score: %.0f / 100", analysis.score));
        pbScore.setProgress((int) Math.round(analysis.score));
        pbScore.setProgressTintList(ColorStateList.valueOf(color));
        tvOutput.setText(FakeIpAnalyzer.report(analysis) + neighbours(analysis));
    }

    /** Other addresses already analysed in the same subnet (this is what subnet-scoped duplicates mean). */
    private String neighbours(FakeIpAnalyzer.Analysis analysis) {
        List<IPDatabaseHelper.HistoryEntry> others = dbHelper.findInSubnet(
                analysis.subnet.network(), analysis.subnet.prefixLen(), analysis.canonical);
        StringBuilder sb = new StringBuilder("\n\n=== SUBNET HISTORY ===\n");
        sb.append(others.size()).append(" other address(es) analysed in ")
          .append(analysis.subnet.network()).append("/").append(analysis.subnet.prefixLen());
        for (int i = 0; i < others.size() && i < 5; i++) {
            sb.append("\n  ").append(others.get(i).ipAddress).append("  ").append(others.get(i).verdictText());
        }
        return sb.toString();
    }

    private static int colorFor(String label) {
        switch (label) {
            case FakeIpFIS.GENUINE:
                return R.color.verdictGenuine;
            case FakeIpFIS.QUESTIONABLE:
                return R.color.verdictQuestionable;
            case FakeIpFIS.SUSPICIOUS:
                return R.color.verdictSuspicious;
            default:
                return R.color.verdictFake;
        }
    }
}
