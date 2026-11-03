package com.example.packetviewer.is2;

import android.app.AlertDialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.example.packetviewer.R;
import com.example.packetviewer.is2.database.IPDatabaseHelper;

import java.util.List;

/**
 * IS2, tab 2: History.
 *
 * Reads every analysed IP and its fuzzy verdict from SQLite (via IPDatabaseHelper)
 * and renders them in a ListView, newest first. Long-press an entry
 * to remove just that IP (with a confirmation dialog); the "Clear
 * History" button wipes the whole table.
 */
public class HistoryFragment extends Fragment {

    private ListView lvHistory;
    private TextView tvEmptyState;
    private TextView tvCount;
    private Button btnClearHistory;
    private IPDatabaseHelper dbHelper;
    private ArrayAdapter<IPDatabaseHelper.HistoryEntry> adapter;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                              @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_history, container, false);

        lvHistory = view.findViewById(R.id.lvHistory);
        tvEmptyState = view.findViewById(R.id.tvEmptyState);
        tvCount = view.findViewById(R.id.tvCount);
        btnClearHistory = view.findViewById(R.id.btnClearHistory);

        dbHelper = new IPDatabaseHelper(requireContext());

        loadHistoryData();

        // Long-press a row -> confirm -> delete only that stored IP
        lvHistory.setOnItemLongClickListener((parent, itemView, position, id) -> {
            IPDatabaseHelper.HistoryEntry entry = adapter.getItem(position);
            if (entry != null) {
                confirmRemove(entry);
            }
            return true; // consume the long-press
        });

        btnClearHistory.setOnClickListener(v -> {
            dbHelper.clearAllHistory();
            loadHistoryData();
            Toast.makeText(getContext(), "SQLite history cleared!", Toast.LENGTH_SHORT).show();
        });

        return view;
    }

    @Override
    public void onResume() {
        super.onResume();
        loadHistoryData(); // refresh in case a new IP was analysed on the Detector tab
    }

    private void loadHistoryData() {
        List<IPDatabaseHelper.HistoryEntry> ipHistoryList = dbHelper.getAllHistoryEntries();

        adapter = new ArrayAdapter<>(requireContext(), android.R.layout.simple_list_item_1, ipHistoryList);
        lvHistory.setAdapter(adapter);

        boolean isEmpty = ipHistoryList.isEmpty();
        lvHistory.setVisibility(isEmpty ? View.GONE : View.VISIBLE);
        tvEmptyState.setVisibility(isEmpty ? View.VISIBLE : View.GONE);

        tvCount.setText("Total analysed IPs: " + dbHelper.getTestedCount());
    }

    private void confirmRemove(IPDatabaseHelper.HistoryEntry entry) {
        new AlertDialog.Builder(requireContext())
                .setTitle("Remove stored IP?")
                .setMessage("\"" + entry.ipAddress + "\" and its stored verdict will be deleted from the database.\n\n"
                        + "You can analyse it again afterwards without the 'already analysed' prompt.")
                .setIcon(android.R.drawable.ic_dialog_alert)
                .setPositiveButton("Remove", (dialog, which) -> {
                    if (dbHelper.deleteTestedIP(entry.id)) {
                        Toast.makeText(getContext(), "Removed " + entry.ipAddress, Toast.LENGTH_SHORT).show();
                    } else {
                        Toast.makeText(getContext(), "Could not remove that entry.", Toast.LENGTH_SHORT).show();
                    }
                    loadHistoryData();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }
}
