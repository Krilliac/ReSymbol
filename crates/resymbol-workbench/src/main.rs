#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use eframe::egui;
use resymbol_workbench::WorkbenchApp;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        persist_window: !cfg!(feature = "screenshot"),
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1_440.0, 900.0])
            .with_min_inner_size([1_024.0, 680.0])
            .with_title("ReSymbol Workbench"),
        ..Default::default()
    };

    eframe::run_native(
        "ReSymbol Workbench",
        options,
        Box::new(|creation_context| Ok(Box::new(WorkbenchApp::new(creation_context)))),
    )
}
