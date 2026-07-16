//! Desktop workbench for evidence-first ReSymbol analysis and export review.

mod app;
pub mod console;
mod console_host;
mod graph;
mod model;
mod review_state;
mod theme;
mod worker;

pub use app::WorkbenchApp;
