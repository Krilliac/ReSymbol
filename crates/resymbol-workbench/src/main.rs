#![cfg_attr(
    all(target_os = "windows", not(feature = "screenshot")),
    windows_subsystem = "windows"
)]

use eframe::egui;
use resymbol_workbench::WorkbenchApp;

const DEFAULT_VIEWPORT_SIZE: [f32; 2] = [1_440.0, 900.0];

fn main() -> eframe::Result {
    let viewport_size = screenshot_viewport_size();
    let options = eframe::NativeOptions {
        persist_window: !cfg!(feature = "screenshot"),
        persistence_path: screenshot_persistence_path(),
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(viewport_size)
            .with_min_inner_size([1_024.0, 680.0])
            .with_clamp_size_to_monitor_size(!cfg!(feature = "screenshot"))
            .with_title("ReSymbol Workbench"),
        ..Default::default()
    };

    eframe::run_native(
        "ReSymbol Workbench",
        options,
        Box::new(|creation_context| Ok(Box::new(WorkbenchApp::new(creation_context)))),
    )
}

fn screenshot_persistence_path() -> Option<std::path::PathBuf> {
    if !cfg!(feature = "screenshot") {
        return None;
    }
    let screenshot = std::env::var_os("RESYMBOL_WORKBENCH_SCREENSHOT_TO")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("resymbol-workbench-screenshot.png"));
    let mut state = screenshot.into_os_string();
    state.push(".state.ron");
    Some(state.into())
}

fn screenshot_viewport_size() -> [f32; 2] {
    #[cfg(feature = "screenshot")]
    if let Ok(value) = std::env::var("RESYMBOL_WORKBENCH_SCREENSHOT_VIEWPORT_POINTS") {
        let (width, height) = value.split_once(',').unwrap_or_else(|| {
            panic!("invalid screenshot viewport {value:?}; expected width,height")
        });
        let width = width
            .parse::<f32>()
            .unwrap_or_else(|error| panic!("invalid screenshot viewport width {width:?}: {error}"));
        let height = height.parse::<f32>().unwrap_or_else(|error| {
            panic!("invalid screenshot viewport height {height:?}: {error}")
        });
        assert!(
            width.is_finite() && height.is_finite() && width >= 640.0 && height >= 480.0,
            "screenshot viewport must be finite and at least 640x480 points"
        );
        return [width, height];
    }

    DEFAULT_VIEWPORT_SIZE
}
