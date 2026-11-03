package com.example.packetviewer.cn;

import androidx.fragment.app.Fragment;

import com.example.packetviewer.ui.SectionFragment;

/**
 * Section 1: CN (Computer Networks).
 *   Viewer     - interactive RFC 791 / RFC 8200 header grids
 *   Subnet     - CIDR subnet calculator (calculate, split, VLSM)
 *   Transition - NAT64 translation, tunneling and dual-stack with computed latency/throughput
 */
public class CnSectionFragment extends SectionFragment {

    private static final String[] TITLES = {"Viewer", "Subnet", "Transition"};

    @Override
    protected String[] pageTitles() {
        return TITLES;
    }

    @Override
    protected Fragment createPage(int position) {
        switch (position) {
            case 0:
                return new ViewerFragment();
            case 1:
                return new SubnetFragment();
            case 2:
                return new TransitionFragment();
            default:
                throw new IllegalStateException("Unexpected CN page: " + position);
        }
    }
}
