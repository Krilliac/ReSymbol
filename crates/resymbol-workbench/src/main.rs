#![forbid(unsafe_code)]

mod app;
mod theme;
mod worker;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    app::run()
}
