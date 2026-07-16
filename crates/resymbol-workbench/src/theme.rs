//! Persisted workbench themes and semantic color tokens.
//!
//! Semantic colors are intentionally independent from widget state. Callers
//! must pair them with visible text or icons instead of relying on color alone.

use eframe::egui::{self, Color32, FontId, Stroke, TextStyle, style::WidgetVisuals};
use serde::{Deserialize, Serialize};

/// A user-selectable, persistence-safe workbench theme.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThemePreset {
    /// Low-glare charcoal surfaces with restrained teal interaction accents.
    #[default]
    Graphite,
    /// Soft-neutral light surfaces with the same semantic color meanings.
    Light,
    /// Dense navy technical workspace inspired by established disassemblers.
    IdaInspired,
    /// Compact light-gray presentation inspired by classic Windows debuggers.
    ClassicDebugger,
}

impl ThemePreset {
    /// Every currently supported preset in stable preference-menu order.
    pub const ALL: [Self; 4] = [
        Self::Graphite,
        Self::Light,
        Self::IdaInspired,
        Self::ClassicDebugger,
    ];

    /// Short user-facing preset name.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Graphite => "Graphite",
            Self::Light => "Light",
            Self::IdaInspired => "IDA-inspired",
            Self::ClassicDebugger => "Classic Debugger",
        }
    }

    /// Semantic and structural colors for custom workbench widgets.
    #[must_use]
    pub fn semantic_colors(self) -> SemanticColors {
        match self {
            Self::Graphite => SemanticColors {
                canvas: Color32::from_rgb(0x11, 0x14, 0x19),
                panel: Color32::from_rgb(0x17, 0x1b, 0x21),
                raised: Color32::from_rgb(0x1e, 0x24, 0x2c),
                hover: Color32::from_rgb(0x27, 0x32, 0x3d),
                selection: Color32::from_rgb(0x16, 0x58, 0x55),
                border: Color32::from_rgb(0x5a, 0x6f, 0x78),
                primary_text: Color32::from_rgb(0xf2, 0xf5, 0xf7),
                secondary_text: Color32::from_rgb(0xb8, 0xc2, 0xcc),
                exact_extracted: Color32::from_rgb(0x56, 0xe0, 0xcf),
                healthy: Color32::from_rgb(0x72, 0xe6, 0x94),
                warning_conflict: Color32::from_rgb(0xff, 0xca, 0x55),
                plugin_provenance: Color32::from_rgb(0xd1, 0xa6, 0xff),
                inferred: Color32::from_rgb(0x9b, 0xcb, 0xff),
                destructive_quarantined: Color32::from_rgb(0xff, 0x91, 0xa0),
                fallback: Color32::from_rgb(0xc0, 0xc8, 0xd0),
                focus: Color32::from_rgb(0x67, 0xe8, 0xf9),
            },
            Self::Light => SemanticColors {
                canvas: Color32::from_rgb(0xf5, 0xf7, 0xf9),
                panel: Color32::WHITE,
                raised: Color32::from_rgb(0xed, 0xf1, 0xf4),
                hover: Color32::from_rgb(0xdf, 0xe8, 0xeb),
                selection: Color32::from_rgb(0xcd, 0xeb, 0xe7),
                border: Color32::from_rgb(0x75, 0x85, 0x8c),
                primary_text: Color32::from_rgb(0x18, 0x21, 0x26),
                secondary_text: Color32::from_rgb(0x4f, 0x5f, 0x66),
                exact_extracted: Color32::from_rgb(0x00, 0x6f, 0x63),
                healthy: Color32::from_rgb(0x16, 0x73, 0x33),
                warning_conflict: Color32::from_rgb(0x89, 0x5b, 0x00),
                plugin_provenance: Color32::from_rgb(0x6e, 0x3e, 0x9e),
                inferred: Color32::from_rgb(0x24, 0x5b, 0xa6),
                destructive_quarantined: Color32::from_rgb(0xa5, 0x26, 0x2d),
                fallback: Color32::from_rgb(0x52, 0x61, 0x68),
                focus: Color32::from_rgb(0x00, 0x5f, 0x87),
            },
            Self::IdaInspired => SemanticColors {
                canvas: Color32::from_rgb(0x0c, 0x18, 0x30),
                panel: Color32::from_rgb(0x12, 0x21, 0x3d),
                raised: Color32::from_rgb(0x19, 0x2b, 0x4c),
                hover: Color32::from_rgb(0x20, 0x3a, 0x61),
                selection: Color32::from_rgb(0x16, 0x4d, 0x6e),
                border: Color32::from_rgb(0x5c, 0x79, 0x9a),
                primary_text: Color32::from_rgb(0xea, 0xf4, 0xff),
                secondary_text: Color32::from_rgb(0xc1, 0xd5, 0xe5),
                exact_extracted: Color32::from_rgb(0x62, 0xe9, 0xe1),
                healthy: Color32::from_rgb(0x82, 0xeb, 0x9a),
                warning_conflict: Color32::from_rgb(0xff, 0xd1, 0x66),
                plugin_provenance: Color32::from_rgb(0xdf, 0xba, 0xff),
                inferred: Color32::from_rgb(0xa8, 0xd6, 0xff),
                destructive_quarantined: Color32::from_rgb(0xff, 0x98, 0xa0),
                fallback: Color32::from_rgb(0xc2, 0xd2, 0xdf),
                focus: Color32::from_rgb(0x71, 0xd7, 0xff),
            },
            Self::ClassicDebugger => SemanticColors {
                canvas: Color32::from_rgb(0xd4, 0xd0, 0xc8),
                panel: Color32::from_rgb(0xf1, 0xf1, 0xef),
                raised: Color32::WHITE,
                hover: Color32::from_rgb(0xe1, 0xe8, 0xf2),
                selection: Color32::from_rgb(0xc4, 0xd8, 0xf0),
                border: Color32::from_rgb(0x70, 0x70, 0x70),
                primary_text: Color32::from_rgb(0x11, 0x11, 0x11),
                secondary_text: Color32::from_rgb(0x4a, 0x4a, 0x4a),
                exact_extracted: Color32::from_rgb(0x00, 0x64, 0x5b),
                healthy: Color32::from_rgb(0x0f, 0x58, 0x24),
                warning_conflict: Color32::from_rgb(0x7a, 0x46, 0x00),
                plugin_provenance: Color32::from_rgb(0x62, 0x35, 0x9b),
                inferred: Color32::from_rgb(0x24, 0x4e, 0x8a),
                destructive_quarantined: Color32::from_rgb(0xa4, 0x13, 0x1f),
                fallback: Color32::from_rgb(0x4a, 0x4a, 0x4a),
                focus: Color32::BLACK,
            },
        }
    }

    /// Apply this preset to the active egui context.
    ///
    /// Existing spacing, margins, and interaction sizes are preserved. Only
    /// colors and the expected proportional/monospace font families change.
    pub fn apply(self, context: &egui::Context) {
        let theme = match self {
            Self::Graphite | Self::IdaInspired => egui::Theme::Dark,
            Self::Light | Self::ClassicDebugger => egui::Theme::Light,
        };
        context.set_theme(theme);

        let colors = self.semantic_colors();
        let mut style = (*context.style()).clone();
        style.visuals = themed_visuals(self, colors);
        preserve_density_and_set_font_families(&mut style);
        context.set_style(style);
    }
}

/// Theme-independent meanings used by status text, icons, badges, and focus rings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticColors {
    pub canvas: Color32,
    pub panel: Color32,
    pub raised: Color32,
    pub hover: Color32,
    pub selection: Color32,
    pub border: Color32,
    pub primary_text: Color32,
    pub secondary_text: Color32,
    /// Verified or deterministically extracted information.
    pub exact_extracted: Color32,
    /// Healthy plugins and completed operations.
    pub healthy: Color32,
    /// Conflicts, warnings, or states requiring review.
    pub warning_conflict: Color32,
    /// Plugin origin; provenance is not a truth or confidence status.
    pub plugin_provenance: Color32,
    /// Explicitly inferred or hypothetical information.
    pub inferred: Color32,
    /// Failures, quarantine, and destructive operations.
    pub destructive_quarantined: Color32,
    /// Unavailable information and automatic fallbacks.
    pub fallback: Color32,
    /// Keyboard focus and the strongest interaction outline.
    pub focus: Color32,
}

fn themed_visuals(preset: ThemePreset, colors: SemanticColors) -> egui::Visuals {
    let mut visuals = match preset {
        ThemePreset::Graphite | ThemePreset::IdaInspired => egui::Visuals::dark(),
        ThemePreset::Light | ThemePreset::ClassicDebugger => egui::Visuals::light(),
    };

    visuals.override_text_color = None;
    visuals.weak_text_color = Some(colors.secondary_text);
    visuals.hyperlink_color = colors.inferred;
    visuals.faint_bg_color = colors.raised;
    visuals.extreme_bg_color = colors.canvas;
    visuals.text_edit_bg_color = Some(colors.canvas);
    visuals.code_bg_color = colors.raised;
    visuals.warn_fg_color = colors.warning_conflict;
    visuals.error_fg_color = colors.destructive_quarantined;
    visuals.window_fill = colors.panel;
    visuals.panel_fill = colors.canvas;
    visuals.window_stroke = Stroke::new(1.0, colors.border);
    visuals.window_corner_radius = egui::CornerRadius::same(4);
    visuals.menu_corner_radius = egui::CornerRadius::same(4);
    visuals.text_cursor.stroke = Stroke::new(2.0, colors.focus);
    visuals.selection.bg_fill = colors.selection;
    visuals.selection.stroke = Stroke::new(1.0, colors.primary_text);
    visuals.striped = true;

    set_widget_colors(
        &mut visuals.widgets.noninteractive,
        colors.panel,
        colors.panel,
        colors.primary_text,
        colors.border,
    );
    set_widget_colors(
        &mut visuals.widgets.inactive,
        colors.raised,
        colors.raised,
        colors.primary_text,
        colors.border,
    );
    set_widget_colors(
        &mut visuals.widgets.hovered,
        colors.hover,
        colors.hover,
        colors.primary_text,
        colors.focus,
    );
    set_widget_colors(
        &mut visuals.widgets.active,
        colors.selection,
        colors.selection,
        colors.primary_text,
        colors.focus,
    );
    set_widget_colors(
        &mut visuals.widgets.open,
        colors.hover,
        colors.hover,
        colors.primary_text,
        colors.focus,
    );

    visuals
}

fn set_widget_colors(
    widget: &mut WidgetVisuals,
    background: Color32,
    weak_background: Color32,
    foreground: Color32,
    outline: Color32,
) {
    widget.bg_fill = background;
    widget.weak_bg_fill = weak_background;
    widget.bg_stroke = Stroke::new(widget.bg_stroke.width.max(1.0), outline);
    widget.fg_stroke = Stroke::new(widget.fg_stroke.width.max(1.0), foreground);
}

fn preserve_density_and_set_font_families(style: &mut egui::Style) {
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.spacing.interact_size.y = 30.0;
    style.spacing.indent = 16.0;
    style
        .text_styles
        .entry(TextStyle::Body)
        .and_modify(|font| *font = FontId::proportional(13.0))
        .or_insert_with(|| FontId::proportional(13.0));
    style
        .text_styles
        .entry(TextStyle::Button)
        .and_modify(|font| *font = FontId::proportional(13.0))
        .or_insert_with(|| FontId::proportional(13.0));
    style
        .text_styles
        .entry(TextStyle::Heading)
        .and_modify(|font| *font = FontId::proportional(18.0))
        .or_insert_with(|| FontId::proportional(18.0));
    style
        .text_styles
        .entry(TextStyle::Small)
        .and_modify(|font| *font = FontId::proportional(11.0))
        .or_insert_with(|| FontId::proportional(11.0));
    style
        .text_styles
        .entry(TextStyle::Monospace)
        .and_modify(|font| *font = FontId::monospace(13.0))
        .or_insert_with(|| FontId::monospace(13.0));
}

/// WCAG relative luminance for an sRGB color. Alpha is intentionally ignored.
#[must_use]
#[cfg(test)]
pub fn relative_luminance(color: Color32) -> f64 {
    fn linear_channel(channel: u8) -> f64 {
        let value = f64::from(channel) / 255.0;
        if value <= 0.040_45 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    }

    0.2126 * linear_channel(color.r())
        + 0.7152 * linear_channel(color.g())
        + 0.0722 * linear_channel(color.b())
}

/// WCAG contrast ratio for two opaque sRGB colors, in the range `1.0..=21.0`.
#[must_use]
#[cfg(test)]
pub fn contrast_ratio(first: Color32, second: Color32) -> f64 {
    let first = relative_luminance(first);
    let second = relative_luminance(second);
    (first.max(second) + 0.05) / (first.min(second) + 0.05)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENHANCED_TEXT_CONTRAST: f64 = 7.0;
    const NORMAL_TEXT_CONTRAST: f64 = 4.5;
    const NON_TEXT_CONTRAST: f64 = 3.0;

    #[test]
    fn presets_round_trip_through_persistence() {
        for preset in ThemePreset::ALL {
            let encoded = serde_json::to_string(&preset).expect("serialize theme preset");
            let decoded: ThemePreset =
                serde_json::from_str(&encoded).expect("deserialize theme preset");
            assert_eq!(decoded, preset);
        }
    }

    #[test]
    fn primary_and_secondary_text_are_readable_on_every_surface() {
        for preset in ThemePreset::ALL {
            let colors = preset.semantic_colors();
            for surface in [colors.canvas, colors.panel, colors.raised] {
                assert_contrast(
                    preset,
                    "primary text",
                    colors.primary_text,
                    surface,
                    ENHANCED_TEXT_CONTRAST,
                );
                assert_contrast(
                    preset,
                    "secondary text",
                    colors.secondary_text,
                    surface,
                    NORMAL_TEXT_CONTRAST,
                );
            }
        }
    }

    #[test]
    fn semantic_status_colors_are_readable_on_workbench_surfaces() {
        for preset in ThemePreset::ALL {
            let colors = preset.semantic_colors();
            let statuses = [
                ("exact/extracted", colors.exact_extracted),
                ("healthy", colors.healthy),
                ("warning/conflict", colors.warning_conflict),
                ("plugin provenance", colors.plugin_provenance),
                ("inferred", colors.inferred),
                ("destructive/quarantined", colors.destructive_quarantined),
                ("fallback", colors.fallback),
            ];

            for (label, foreground) in statuses {
                for surface in [colors.canvas, colors.panel, colors.raised] {
                    assert_contrast(preset, label, foreground, surface, NORMAL_TEXT_CONTRAST);
                }
            }
        }
    }

    #[test]
    fn focus_and_boundaries_remain_visible_without_changing_status_meaning() {
        for preset in ThemePreset::ALL {
            let colors = preset.semantic_colors();
            for surface in [colors.canvas, colors.panel, colors.raised] {
                assert_contrast(preset, "focus", colors.focus, surface, NON_TEXT_CONTRAST);
            }
            assert_contrast(
                preset,
                "panel boundary",
                colors.border,
                colors.panel,
                NON_TEXT_CONTRAST,
            );
            assert_contrast(
                preset,
                "selected text",
                colors.primary_text,
                colors.selection,
                NORMAL_TEXT_CONTRAST,
            );
        }
    }

    fn assert_contrast(
        preset: ThemePreset,
        role: &str,
        foreground: Color32,
        background: Color32,
        minimum: f64,
    ) {
        let actual = contrast_ratio(foreground, background);
        assert!(
            actual >= minimum,
            "{} {role} contrast {actual:.2} is below {minimum:.2}",
            preset.label(),
        );
    }
}
