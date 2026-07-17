//! Desktop workbench for evidence-first ReSymbol analysis and export review.

mod app;
pub mod console;
mod console_host;
mod graph;
mod instruction_actions;
mod model;
mod readiness;
mod review_state;
mod theme;
mod ui_policy;
mod worker;

pub use app::WorkbenchApp;
