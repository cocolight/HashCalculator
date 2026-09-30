#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod format;
mod worker;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([680.0, 460.0])
            .with_min_inner_size([420.0, 320.0])
            .with_title("Hash 计算器"),
        ..Default::default()
    };

    eframe::run_native(
        "Hash Calculator",
        options,
        Box::new(|cc| Ok(Box::new(app::HashApp::new(cc)))),
    )
}
