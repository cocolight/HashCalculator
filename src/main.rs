#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod batch;
mod format;
mod worker;

fn main() -> eframe::Result {
    // 无界面基准入口：`hash_calculator --bench <path>`
    // 复用与 GUI 完全相同的 worker 计算路径，仅用于性能测量与哈希交叉验证。
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "--bench" {
        run_bench(&args[2]);
        return Ok(());
    }

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

/// 无界面基准：调用与 GUI 完全相同的 worker 计算路径，打印结果与吞吐。
/// 结果同时打印到 stdout 并写入 `<path>.bench.txt`，以防 release 的 windows 子系统吞掉 stdout。
fn run_bench(path: &str) {
    let p = std::path::PathBuf::from(path);
    let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);

    let (_handle, rx) = worker::spawn(p, true);

    loop {
        match rx.recv() {
            Ok(worker::WorkerMsg::Progress { .. }) => {}
            Ok(worker::WorkerMsg::Done {
                md5,
                sha256,
                elapsed_ms,
            }) => {
                let mbps = if elapsed_ms > 0 {
                    (size as f64 / 1_048_576.0) / (elapsed_ms as f64 / 1000.0)
                } else {
                    0.0
                };
                let report = format!(
                    "file={path}\nsize={size}\nmd5={md5}\nsha256={sha256}\nelapsed_ms={elapsed_ms}\nthroughput_MBps={mbps:.1}\n"
                );
                print!("{report}");
                use std::io::Write;
                let _ = std::io::stdout().flush();
                let _ = std::fs::write(format!("{path}.bench.txt"), &report);
                break;
            }
            Ok(worker::WorkerMsg::Error(e)) => {
                println!("error={e}");
                break;
            }
            Ok(worker::WorkerMsg::Cancelled) => {
                println!("cancelled");
                break;
            }
            Err(_) => break,
        }
    }
}
