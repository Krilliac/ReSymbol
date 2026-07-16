use eframe::egui::{self, Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Visuals};
use serde::{Deserialize, Serialize};

/// The four supported workbench appearances. Themes are presentation-only:
/// every preset keeps the same layout, status labels, and focus treatment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemePreset {
    #[default]
    Graphite,
    Light,
    IdaInspired,
    ClassicDebugger,
}

impl ThemePreset {
    pub const ALL: [Self; 4] = [
        Self::Graphite,
        Self::Light,
        Self::IdaInspired,
        Self::ClassicDebugger,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Graphite => "Graphite",
            Self::Light => "Light",
            Self::IdaInspired => "IDA-inspired",
            Self::ClassicDebugger => "Classic Debugger",
        }
    }

    pub const fn tokens(self) -> ThemeTokens {
        match self {
            Self::Graphite => ThemeTokens {
                canvas: rgb(0x11, 0x14, 0x19),
                panel: rgb(0x17, 0x1b, 0x21),
                elevated: rgb(0x1e, 0x24, 0x2c),
                border: rgb(0x34, 0x3d, 0x48),
                text: rgb(0xf2, 0xf5, 0xf7),
                muted: rgb(0x87, 0x93, 0xa1),
                accent: rgb(0x2d, 0xd4, 0xbf),
                focus: rgb(0x67, 0xe8, 0xf9),
                exact: rgb(0x2d, 0xd4, 0xbf),
                success: rgb(0x5e, 0xe3, 0x84),
                warning: rgb(0xfb, 0xbf, 0x24),
                plugin: rgb(0xc0, 0x84, 0xfc),
                inferred: rgb(0x93, 0xc5, 0xfd),
                danger: rgb(0xfb, 0x71, 0x85),
                dark: true,
            },
            Self::Light => ThemeTokens {
                canvas: rgb(0xf5, 0xf7, 0xf9),
                panel: rgb(0xff, 0xff, 0xff),
                elevated: rgb(0xed, 0xf1, 0xf4),
                border: rgb(0xb5, 0xbe, 0xc8),
                text: rgb(0x17, 0x20, 0x2a),
                muted: rgb(0x5d, 0x6b, 0x7a),
                accent: rgb(0x08, 0x7f, 0x73),
                focus: rgb(0x00, 0x5f, 0xcc),
                exact: rgb(0x00, 0x6b, 0x62),
                success: rgb(0x18, 0x74, 0x3a),
                warning: rgb(0x8a, 0x4b, 0x00),
                plugin: rgb(0x6f, 0x36, 0xa8),
                inferred: rgb(0x24, 0x5c, 0x9e),
                danger: rgb(0xb4, 0x23, 0x2b),
                dark: false,
            },
            Self::IdaInspired => ThemeTokens {
                canvas: rgb(0x0c, 0x18, 0x30),
                panel: rgb(0x12, 0x21, 0x3d),
                elevated: rgb(0x19, 0x2b, 0x4c),
                border: rgb(0x34, 0x52, 0x77),
                text: rgb(0xea, 0xf4, 0xff),
                muted: rgb(0x8c, 0xa9, 0xc3),
                accent: rgb(0x31, 0xbd, 0xf2),
                focus: rgb(0x71, 0xd7, 0xff),
                exact: rgb(0x49, 0xd8, 0xd0),
                success: rgb(0x73, 0xe2, 0x8f),
                warning: rgb(0xff, 0xd1, 0x66),
                plugin: rgb(0xd6, 0xa3, 0xff),
                inferred: rgb(0x85, 0xc4, 0xff),
                danger: rgb(0xff, 0x7b, 0x86),
                dark: true,
            },
            Self::ClassicDebugger => ThemeTokens {
                canvas: rgb(0xd4, 0xd0, 0xc8),
                panel: rgb(0xf1, 0xf1, 0xef),
                elevated: rgb(0xff, 0xff, 0xff),
                border: rgb(0x70, 0x70, 0x70),
                text: rgb(0x11, 0x11, 0x11),
                muted: rgb(0x4a, 0x4a, 0x4a),
                accent: rgb(0x0a, 0x4e, 0xa3),
                focus: rgb(0x00, 0x00, 0x00),
                exact: rgb(0x00, 0x64, 0x5b),
                success: rgb(0x1e, 0x6e, 0x2f),
                warning: rgb(0x7a, 0x46, 0x00),
                plugin: rgb(0x62, 0x35, 0x9b),
                inferred: rgb(0x24, 0x4e, 0x8a),
                danger: rgb(0xa4, 0x13, 0x1f),
                dark: false,
            },
        }
    }

    pub fn apply(self, ctx: &egui::Context, ui_scale: f32, mono_size: f32) {
        let tokens = self.tokens();
        let mut visuals = if tokens.dark {
            Visuals::dark()
        } else {
            Visuals::light()
        };
        visuals.override_text_color = Some(tokens.text);
        visuals.panel_fill = tokens.panel;
        visuals.window_fill = tokens.panel;
        visuals.extreme_bg_color = tokens.canvas;
        visuals.faint_bg_color = tokens.elevated;
        visuals.code_bg_color = tokens.canvas;
        visuals.hyperlink_color = tokens.accent;
        visuals.warn_fg_color = tokens.warning;
        visuals.error_fg_color = tokens.danger;
        visuals.selection.bg_fill = tokens.accent.gamma_multiply(0.42);
        visuals.selection.stroke = Stroke::new(1.0, tokens.focus);
        visuals.window_stroke = Stroke::new(1.0, tokens.border);
        visuals.window_corner_radius = CornerRadius::same(4);
        visuals.menu_corner_radius = CornerRadius::same(4);
        visuals.widgets.noninteractive.bg_fill = tokens.panel;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, tokens.border);
        visuals.widgets.inactive.bg_fill = tokens.elevated;
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, tokens.border);
        visuals.widgets.hovered.bg_fill = blend(tokens.elevated, tokens.accent, 0.16);
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, tokens.focus);
        visuals.widgets.active.bg_fill = blend(tokens.elevated, tokens.accent, 0.26);
        visuals.widgets.active.bg_stroke = Stroke::new(2.0, tokens.focus);
        visuals.widgets.open.bg_fill = blend(tokens.elevated, tokens.accent, 0.20);
        visuals.widgets.open.bg_stroke = Stroke::new(1.0, tokens.focus);
        visuals.striped = true;

        let mut style = (*ctx.style()).clone();
        style.visuals = visuals;
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 6.0);
        style.spacing.interact_size.y = 30.0;
        style.spacing.indent = 16.0;
        style.text_styles = [
            (
                TextStyle::Small,
                FontId::new(11.0, FontFamily::Proportional),
            ),
            (TextStyle::Body, FontId::new(13.0, FontFamily::Proportional)),
            (
                TextStyle::Button,
                FontId::new(13.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Heading,
                FontId::new(18.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(mono_size, FontFamily::Monospace),
            ),
        ]
        .into();
        ctx.set_style(style);
        ctx.set_pixels_per_point(ui_scale);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ThemeTokens {
    pub canvas: Color32,
    pub panel: Color32,
    pub elevated: Color32,
    pub border: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub focus: Color32,
    pub exact: Color32,
    pub success: Color32,
    pub warning: Color32,
    pub plugin: Color32,
    pub inferred: Color32,
    pub danger: Color32,
    pub dark: bool,
}

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

fn blend(a: Color32, b: Color32, amount: f32) -> Color32 {
    let amount = amount.clamp(0.0, 1.0);
    let channel = |x: u8, y: u8| -> u8 {
        (f32::from(x).mul_add(1.0 - amount, f32::from(y) * amount)).round() as u8
    };
    Color32::from_rgb(
        channel(a.r(), b.r()),
        channel(a.g(), b.g()),
        channel(a.b(), b.b()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_theme_tokens_are_exact() {
        let graphite = ThemePreset::Graphite.tokens();
        assert_eq!(graphite.canvas, Color32::from_rgb(0x11, 0x14, 0x19));
        assert_eq!(graphite.accent, Color32::from_rgb(0x2d, 0xd4, 0xbf));
        assert_eq!(graphite.danger, Color32::from_rgb(0xfb, 0x71, 0x85));

        let light = ThemePreset::Light.tokens();
        assert_eq!(light.panel, Color32::WHITE);
        assert_eq!(light.focus, Color32::from_rgb(0x00, 0x5f, 0xcc));

        let ida = ThemePreset::IdaInspired.tokens();
        assert_eq!(ida.canvas, Color32::from_rgb(0x0c, 0x18, 0x30));
        assert_eq!(ida.plugin, Color32::from_rgb(0xd6, 0xa3, 0xff));

        let classic = ThemePreset::ClassicDebugger.tokens();
        assert_eq!(classic.canvas, Color32::from_rgb(0xd4, 0xd0, 0xc8));
        assert_eq!(classic.accent, Color32::from_rgb(0x0a, 0x4e, 0xa3));
    }
}
