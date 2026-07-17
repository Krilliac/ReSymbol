//! Pure responsive-layout and keyboard-navigation policy for the workbench shell.
//!
//! The egui event loop remains the only owner of UI state. This module only
//! computes presentations and next selections from immutable inputs.

/// Default project-navigation width used by the desktop shell.
pub(crate) const DEFAULT_PROJECT_PANEL_WIDTH: f32 = 220.0;
/// Default evidence-inspector width used by the desktop shell.
pub(crate) const DEFAULT_INSPECTOR_PANEL_WIDTH: f32 = 330.0;

#[cfg(test)]
const DEFAULT_CENTRAL_HORIZONTAL_CHROME: f32 = 26.0;
const MAIN_TAB_FULL_WIDTH: f32 = 112.0;
const MAIN_TAB_COMPACT_WIDTH: f32 = 88.0;
const MAIN_TAB_FULL_SPACING: f32 = 8.0;
const MAIN_TAB_COMPACT_SPACING: f32 = 6.0;
const COMPACT_HEADER_MAX_VIEWPORT_WIDTH: f32 = 1_120.0;
const COMPACT_ACTIVITY_MAX_AVAILABLE_HEIGHT: f32 = 700.0;
// Five 8-point column gaps, a 10-point solid vertical scrollbar in capture mode,
// and two points of rounding headroom.
const FUNCTION_TABLE_CHROME_RESERVE: f32 = 52.0;
const FUNCTION_COLUMN_MINIMUMS: [f32; 6] = [118.0, 92.0, 180.0, 112.0, 138.0, 72.0];
const FUNCTION_COLUMN_EXTRA_WEIGHTS: [f32; 6] = [0.05, 0.0, 0.55, 0.10, 0.30, 0.0];

/// Responsive policy for the fixed header and activity panel around the review area.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ShellChromeLayout {
    pub(crate) compact_header: bool,
    pub(crate) activity_default_height: f32,
    pub(crate) activity_min_height: f32,
    pub(crate) activity_max_height: f32,
}

/// Keep central review content usable at the documented minimum viewport.
#[must_use]
pub(crate) fn shell_chrome_layout(viewport_width: f32, available_height: f32) -> ShellChromeLayout {
    let viewport_width = finite_nonnegative(viewport_width);
    let available_height = finite_nonnegative(available_height);
    let compact_header = viewport_width < COMPACT_HEADER_MAX_VIEWPORT_WIDTH;
    let compact_activity =
        compact_header || available_height < COMPACT_ACTIVITY_MAX_AVAILABLE_HEIGHT;
    ShellChromeLayout {
        compact_header,
        activity_default_height: if compact_activity { 110.0 } else { 190.0 },
        activity_min_height: if compact_activity { 90.0 } else { 110.0 },
        activity_max_height: if compact_activity { 120.0 } else { 420.0 },
    }
}

/// One-row presentation selected for the main task tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MainTabPresentation {
    /// Full labels in fixed-width buttons.
    Full,
    /// Short labels in narrower fixed-width buttons.
    Compact,
    /// One explicit selector containing every tab.
    Menu,
}

impl MainTabPresentation {
    /// Button width for presentations that render one button per tab.
    pub(crate) const fn button_width(self) -> Option<f32> {
        match self {
            Self::Full => Some(MAIN_TAB_FULL_WIDTH),
            Self::Compact => Some(MAIN_TAB_COMPACT_WIDTH),
            Self::Menu => None,
        }
    }

    /// Horizontal gap between tab buttons.
    pub(crate) const fn spacing(self) -> f32 {
        match self {
            Self::Full => MAIN_TAB_FULL_SPACING,
            Self::Compact | Self::Menu => MAIN_TAB_COMPACT_SPACING,
        }
    }
}

/// Choose a tab presentation that cannot wrap at the supplied content width.
#[must_use]
pub(crate) fn main_tab_presentation(available_width: f32, tab_count: usize) -> MainTabPresentation {
    let available_width = finite_nonnegative(available_width);
    if required_tab_width(MainTabPresentation::Full, tab_count) <= available_width {
        MainTabPresentation::Full
    } else if required_tab_width(MainTabPresentation::Compact, tab_count) <= available_width {
        MainTabPresentation::Compact
    } else {
        MainTabPresentation::Menu
    }
}

/// Width needed to render a button presentation on exactly one row.
#[must_use]
pub(crate) fn required_tab_width(presentation: MainTabPresentation, tab_count: usize) -> f32 {
    let Some(button_width) = presentation.button_width() else {
        return 0.0;
    };
    let gaps = tab_count.saturating_sub(1) as f32;
    tab_count as f32 * button_width + gaps * presentation.spacing()
}

/// Conservative central content width with both default side panels open.
#[must_use]
#[cfg(test)]
pub(crate) fn default_review_content_width(viewport_width: f32) -> f32 {
    (finite_nonnegative(viewport_width)
        - DEFAULT_PROJECT_PANEL_WIDTH
        - DEFAULT_INSPECTOR_PANEL_WIDTH
        - DEFAULT_CENTRAL_HORIZONTAL_CHROME)
        .max(0.0)
}

/// Computed widths for the six Function table columns.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct FunctionTableLayout {
    pub(crate) widths: [f32; 6],
    pub(crate) horizontal_overflow: bool,
}

impl FunctionTableLayout {
    /// Width allocated inside the explicit horizontal scroll area.
    #[must_use]
    pub(crate) fn content_width(self) -> f32 {
        self.widths.iter().sum::<f32>() + FUNCTION_TABLE_CHROME_RESERVE
    }
}

/// Fit all Function columns when the central pane has sufficient width.
///
/// Small panes retain readable minimums so the caller's horizontal scroll area
/// can expose every column instead of hiding one.
#[must_use]
pub(crate) fn function_table_layout(available_width: f32) -> FunctionTableLayout {
    let available_width = finite_nonnegative(available_width);
    let usable_width = (available_width - FUNCTION_TABLE_CHROME_RESERVE).max(0.0);
    let minimum_width: f32 = FUNCTION_COLUMN_MINIMUMS.iter().sum();
    let horizontal_overflow = usable_width < minimum_width;
    let extra = (usable_width - minimum_width).max(0.0);
    let mut widths = FUNCTION_COLUMN_MINIMUMS;
    for (width, weight) in widths.iter_mut().zip(FUNCTION_COLUMN_EXTRA_WEIGHTS.iter()) {
        *width += extra * weight;
    }
    FunctionTableLayout {
        widths,
        horizontal_overflow,
    }
}

/// Direction for cycling through a finite sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CycleDirection {
    Previous,
    Next,
}

/// Cycle an index with deterministic wrapping.
#[must_use]
pub(crate) fn cycle_index(
    current: usize,
    count: usize,
    direction: CycleDirection,
) -> Option<usize> {
    if count == 0 {
        return None;
    }
    let current = current % count;
    Some(match direction {
        CycleDirection::Previous => current.checked_sub(1).unwrap_or(count - 1),
        CycleDirection::Next => (current + 1) % count,
    })
}

/// Keyboard movement over the current filtered and sorted Function rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowNavigation {
    Previous,
    Next,
    PagePrevious,
    PageNext,
    First,
    Last,
}

/// Select a stable projection identifier from the visible row order.
#[must_use]
pub(crate) fn navigate_visible_selection(
    visible_projection_indices: &[usize],
    current_projection_index: Option<usize>,
    navigation: RowNavigation,
    page_rows: usize,
) -> Option<usize> {
    let last = visible_projection_indices.len().checked_sub(1)?;
    if navigation == RowNavigation::First {
        return visible_projection_indices.first().copied();
    }
    if navigation == RowNavigation::Last {
        return visible_projection_indices.last().copied();
    }

    let current_position = current_projection_index.and_then(|current| {
        visible_projection_indices
            .iter()
            .position(|value| *value == current)
    });
    let next_position = match current_position {
        Some(position) => match navigation {
            RowNavigation::Previous => position.saturating_sub(1),
            RowNavigation::Next => position.saturating_add(1).min(last),
            RowNavigation::PagePrevious => position.saturating_sub(page_rows.max(1)),
            RowNavigation::PageNext => position.saturating_add(page_rows.max(1)).min(last),
            RowNavigation::First | RowNavigation::Last => unreachable!("handled above"),
        },
        None => match navigation {
            RowNavigation::Previous | RowNavigation::PagePrevious => last,
            RowNavigation::Next | RowNavigation::PageNext => 0,
            RowNavigation::First | RowNavigation::Last => unreachable!("handled above"),
        },
    };
    visible_projection_indices.get(next_position).copied()
}

fn finite_nonnegative(value: f32) -> f32 {
    if value.is_finite() {
        value.max(0.0)
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN_TAB_COUNT: usize = 8;

    #[test]
    fn capture_viewport_uses_one_row_of_compact_tabs() {
        let available = default_review_content_width(1_440.0);
        let presentation = main_tab_presentation(available, MAIN_TAB_COUNT);

        assert_eq!(presentation, MainTabPresentation::Compact);
        assert!(required_tab_width(presentation, MAIN_TAB_COUNT) <= available);
    }

    #[test]
    fn minimum_viewport_uses_one_explicit_tab_menu() {
        let available = default_review_content_width(1_024.0);

        assert_eq!(
            main_tab_presentation(available, MAIN_TAB_COUNT),
            MainTabPresentation::Menu
        );
    }

    #[test]
    fn documented_viewports_choose_readable_shell_chrome() {
        let default = shell_chrome_layout(1_440.0, 788.0);
        assert!(!default.compact_header);
        assert_eq!(default.activity_default_height, 190.0);

        let minimum = shell_chrome_layout(1_024.0, 568.0);
        assert!(minimum.compact_header);
        assert_eq!(minimum.activity_default_height, 110.0);
        assert_eq!(minimum.activity_min_height, 90.0);
        assert_eq!(minimum.activity_max_height, 120.0);
    }

    #[test]
    fn function_columns_fit_the_default_capture_central_pane() {
        let available = default_review_content_width(1_440.0);
        let layout = function_table_layout(available);

        assert!(!layout.horizontal_overflow);
        assert!(layout.content_width() <= available + f32::EPSILON);
    }

    #[test]
    fn narrow_function_table_retains_every_readable_minimum() {
        let layout = function_table_layout(default_review_content_width(1_024.0));

        assert!(layout.horizontal_overflow);
        assert_eq!(layout.widths, FUNCTION_COLUMN_MINIMUMS);
        assert!(layout.content_width() > default_review_content_width(1_024.0));
    }

    #[test]
    fn sequence_cycle_wraps_in_both_directions() {
        assert_eq!(cycle_index(7, 8, CycleDirection::Next), Some(0));
        assert_eq!(cycle_index(0, 8, CycleDirection::Previous), Some(7));
        assert_eq!(cycle_index(3, 0, CycleDirection::Next), None);
    }

    #[test]
    fn row_navigation_uses_filtered_sorted_order_and_stable_ids() {
        let visible = [19, 4, 27, 8, 13];

        assert_eq!(
            navigate_visible_selection(&visible, Some(4), RowNavigation::Next, 3),
            Some(27)
        );
        assert_eq!(
            navigate_visible_selection(&visible, Some(8), RowNavigation::PagePrevious, 2),
            Some(4)
        );
        assert_eq!(
            navigate_visible_selection(&visible, Some(4), RowNavigation::PageNext, 2),
            Some(8)
        );
        assert_eq!(
            navigate_visible_selection(&visible, Some(19), RowNavigation::Previous, 3),
            Some(19)
        );
        assert_eq!(
            navigate_visible_selection(&visible, Some(13), RowNavigation::Next, 3),
            Some(13)
        );
    }

    #[test]
    fn row_navigation_recovers_when_selection_is_filtered_out() {
        let visible = [2, 6, 9];

        assert_eq!(
            navigate_visible_selection(&visible, Some(7), RowNavigation::Next, 10),
            Some(2)
        );
        assert_eq!(
            navigate_visible_selection(&visible, Some(7), RowNavigation::Previous, 10),
            Some(9)
        );
        assert_eq!(
            navigate_visible_selection(&visible, None, RowNavigation::First, 10),
            Some(2)
        );
        assert_eq!(
            navigate_visible_selection(&visible, None, RowNavigation::Last, 10),
            Some(9)
        );
        assert_eq!(
            navigate_visible_selection(&[], None, RowNavigation::Next, 10),
            None
        );
    }
}
