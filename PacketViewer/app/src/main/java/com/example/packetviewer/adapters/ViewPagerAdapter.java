package com.example.packetviewer.adapters;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.viewpager2.adapter.FragmentStateAdapter;

import com.example.packetviewer.cn.CnSectionFragment;
import com.example.packetviewer.is2.Is2SectionFragment;

/**
 * Backs the top-level ViewPager2 in MainActivity with the two sections:
 *  0 -> CnSectionFragment  (Computer Networks: Viewer, Subnet, Transition)
 *  1 -> Is2SectionFragment (Intelligent Systems: Detector, History)
 */
public class ViewPagerAdapter extends FragmentStateAdapter {

    public ViewPagerAdapter(@NonNull FragmentActivity fragmentActivity) {
        super(fragmentActivity);
    }

    @NonNull
    @Override
    public Fragment createFragment(int position) {
        switch (position) {
            case 0:
                return new CnSectionFragment();
            case 1:
                return new Is2SectionFragment();
            default:
                throw new IllegalStateException("Unexpected section position: " + position);
        }
    }

    @Override
    public int getItemCount() {
        return 2;
    }
}
