package com.example.packetviewer.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.viewpager2.adapter.FragmentStateAdapter;
import androidx.viewpager2.widget.ViewPager2;

import com.example.packetviewer.R;
import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;

/**
 * Shared base for the two top-level sections (CN and IS2). Each section is a
 * screen with its own row of tabs and a swipeable pager of pages; a subclass
 * only says what its tab titles and pages are.
 */
public abstract class SectionFragment extends Fragment {

    private ViewPager2 pager;
    private TabLayoutMediator mediator;

    /** Tab titles, one per page. */
    protected abstract String[] pageTitles();

    /** The fragment shown for page {@code position}. */
    protected abstract Fragment createPage(int position);

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                              @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_section, container, false);

        TabLayout tabLayout = view.findViewById(R.id.sectionTabLayout);
        pager = view.findViewById(R.id.sectionViewPager);
        pager.setAdapter(new PagesAdapter(this));

        final String[] titles = pageTitles();
        mediator = new TabLayoutMediator(tabLayout, pager,
                (tab, position) -> tab.setText(titles[position]));
        mediator.attach();

        return view;
    }

    @Override
    public void onDestroyView() {
        if (mediator != null) {
            mediator.detach();
            mediator = null;
        }
        if (pager != null) {
            pager.setAdapter(null);
            pager = null;
        }
        super.onDestroyView();
    }

    /** Pages live in this fragment's child FragmentManager. */
    private static class PagesAdapter extends FragmentStateAdapter {

        private final SectionFragment owner;

        PagesAdapter(@NonNull SectionFragment owner) {
            super(owner);
            this.owner = owner;
        }

        @NonNull
        @Override
        public Fragment createFragment(int position) {
            return owner.createPage(position);
        }

        @Override
        public int getItemCount() {
            return owner.pageTitles().length;
        }
    }
}
