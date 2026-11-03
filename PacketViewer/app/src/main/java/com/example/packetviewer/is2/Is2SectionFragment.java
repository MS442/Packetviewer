package com.example.packetviewer.is2;

import androidx.fragment.app.Fragment;

import com.example.packetviewer.ui.SectionFragment;

/**
 * Section 2: IS2 (Intelligent Systems).
 *   Detector - Mamdani fuzzy inference system that scores how likely an IP is fake
 *   History  - SQLite log of analysed addresses with their verdicts (long-press to remove)
 */
public class Is2SectionFragment extends SectionFragment {

    private static final String[] TITLES = {"Detector", "History"};

    @Override
    protected String[] pageTitles() {
        return TITLES;
    }

    @Override
    protected Fragment createPage(int position) {
        switch (position) {
            case 0:
                return new DetectorFragment();
            case 1:
                return new HistoryFragment();
            default:
                throw new IllegalStateException("Unexpected IS2 page: " + position);
        }
    }
}
