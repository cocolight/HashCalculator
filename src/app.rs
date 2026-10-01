//! egui 主应用：文件选择、哈希设置、计算结果、哈希验证、状态栏 + 进度条。

use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::SystemTime;

use egui::{Color32, RichText, TextEdit};

use crate::format;
use crate::worker::{self, WorkerHandle, WorkerMsg};

pub struct HashApp {
    file_path: String,
    file_name: String,
    file_size: u64,
    file_modified: Option<SystemTime>,
    upper_case: bool,

    md5_result: String,
    sha256_result: String,
    result_text: String,

    md5_verify: String,
    sha256_verify: String,

    status: String,
    status_error: bool,
    progress: f32,
    elapsed_ms: u128,

    worker: Option<WorkerHandle>,
    rx: Option<Receiver<WorkerMsg>>,
}

impl HashApp {
    /// 注册系统中文字体到 egui，否则 CJK 字符渲染为方框（tofu）。
    /// 按优先级探测常见系统 CJK 字体（Windows > Linux > macOS）。
    fn install_cjk_fonts(ctx: &egui::Context) {
        const CANDIDATES: &[&str] = &[
            // Windows
            r"C:\Windows\Fonts\msyh.ttc",   // 微软雅黑
            r"C:\Windows\Fonts\msyh.ttf",
            r"C:\Windows\Fonts\msyhbd.ttc",
            r"C:\Windows\Fonts\simhei.ttf", // 黑体
            r"C:\Windows\Fonts\simsun.ttc", // 宋体
            // Linux（主流发行版 Noto/文泉驿）
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
            // macOS
            "/System/Library/Fonts/PingFang.ttc",
            "/System/Library/Fonts/STHeiti Light.ttc",
        ];

        let mut font_data: Vec<(String, Vec<u8>)> = Vec::new();
        for (i, path) in CANDIDATES.iter().enumerate() {
            if let Ok(bytes) = std::fs::read(path) {
                font_data.push((format!("cjk_{i}"), bytes));
                break;
            }
        }

        if font_data.is_empty() {
            return; // 未找到系统 CJK 字体，维持默认（仅英文可用）
        }

        let mut fonts = egui::FontDefinitions::default();
        for (name, bytes) in font_data {
            fonts.font_data.insert(
                name.clone(),
                egui::FontData::from_owned(bytes).into(),
            );
            // 追加到 Proportional 与 Monospace 的回退链末尾：
            // ASCII 仍用默认字体渲染，CJK 落到中文字体
            for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                if let Some(list) = fonts.families.get_mut(&family) {
                    list.push(name.clone());
                }
            }
        }
        ctx.set_fonts(fonts);
    }

    pub fn new(cc: &eframe::CreationContext) -> Self {
        Self::install_cjk_fonts(&cc.egui_ctx);
        Self {
            file_path: String::new(),
            file_name: String::new(),
            file_size: 0,
            file_modified: None,
            upper_case: true,
            md5_result: String::new(),
            sha256_result: String::new(),
            result_text: String::new(),
            md5_verify: String::new(),
            sha256_verify: String::new(),
            status: "就绪".into(),
            status_error: false,
            progress: 0.0,
            elapsed_ms: 0,
            worker: None,
            rx: None,
        }
    }

    fn is_calculating(&self) -> bool {
        self.worker.is_some()
    }

    fn pick_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            self.set_file(path);
        }
    }

    fn set_file(&mut self, path: PathBuf) {
        self.file_path = path.to_string_lossy().to_string();
        self.file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        match std::fs::metadata(&path) {
            Ok(meta) => {
                self.file_size = meta.len();
                self.file_modified = meta.modified().ok();
            }
            Err(_) => {
                self.file_size = 0;
                self.file_modified = None;
            }
        }
        self.md5_result.clear();
        self.sha256_result.clear();
        self.progress = 0.0;
        self.elapsed_ms = 0;
        self.update_result_text();
        self.set_status("已选择文件", false);
    }

    fn start_calc(&mut self) {
        if self.file_path.is_empty() {
            self.set_status("请选择文件", true);
            return;
        }
        let path = PathBuf::from(&self.file_path);
        if !path.exists() {
            self.set_status("文件不存在", true);
            return;
        }
        let (handle, rx) = worker::spawn(path, self.upper_case);
        self.worker = Some(handle);
        self.rx = Some(rx);
        self.md5_result.clear();
        self.sha256_result.clear();
        self.progress = 0.0;
        self.elapsed_ms = 0;
        self.update_result_text();
        self.set_status("计算中...", false);
    }

    fn cancel_calc(&mut self) {
        if let Some(w) = &self.worker {
            w.cancel();
            self.set_status("正在取消...", false);
        }
    }

    fn clear_all(&mut self) {
        if self.is_calculating() {
            self.cancel_calc();
            return;
        }
        self.file_path.clear();
        self.file_name.clear();
        self.file_size = 0;
        self.file_modified = None;
        self.md5_result.clear();
        self.sha256_result.clear();
        self.md5_verify.clear();
        self.sha256_verify.clear();
        self.progress = 0.0;
        self.elapsed_ms = 0;
        self.update_result_text();
        self.set_status("就绪", false);
    }

    fn copy_result(&mut self) {
        if self.result_text.is_empty() {
            self.set_status("请先计算，无内容可复制", true);
            return;
        }
        match arboard::Clipboard::new().and_then(|mut cb| cb.set_text(self.result_text.clone())) {
            Ok(_) => self.set_status("结果已复制到剪贴板", false),
            Err(e) => self.set_status(&format!("复制失败: {e}"), true),
        }
    }

    fn verify(&mut self) {
        if self.md5_result.is_empty() && self.sha256_result.is_empty() {
            self.set_status("请先计算哈希值", true);
            return;
        }
        let m = self.md5_verify.trim();
        let s = self.sha256_verify.trim();
        if m.is_empty() && s.is_empty() {
            self.set_status("请至少填写一个待验证的哈希值", true);
            return;
        }
        self.set_status("验证完成", false);
    }

    fn md5_verify_ok(&self) -> Option<bool> {
        let v = self.md5_verify.trim();
        if v.is_empty() || self.md5_result.is_empty() {
            return None;
        }
        Some(self.md5_result.eq_ignore_ascii_case(v))
    }

    fn sha256_verify_ok(&self) -> Option<bool> {
        let v = self.sha256_verify.trim();
        if v.is_empty() || self.sha256_result.is_empty() {
            return None;
        }
        Some(self.sha256_result.eq_ignore_ascii_case(v))
    }

    fn update_result_text(&mut self) {
        use std::fmt::Write;
        let mut s = String::new();
        let _ = writeln!(s, "文件名称: {}", self.file_name);
        let _ = writeln!(s, "文件大小: {}", format::format_size(self.file_size));
        let _ = writeln!(
            s,
            "修改日期: {}",
            self.file_modified
                .map(format::format_time)
                .unwrap_or_else(|| "-".to_string())
        );
        let _ = writeln!(
            s,
            "MD5:  {}",
            if self.md5_result.is_empty() {
                "-".to_string()
            } else {
                self.md5_result.clone()
            }
        );
        let _ = writeln!(
            s,
            "SHA-256:  {}",
            if self.sha256_result.is_empty() {
                "-".to_string()
            } else {
                self.sha256_result.clone()
            }
        );
        self.result_text = s;
    }

    fn set_status(&mut self, msg: &str, err: bool) {
        self.status = msg.into();
        self.status_error = err;
    }

    fn poll_worker(&mut self) {
        // take 出 rx 避免与 self 的可变借用冲突
        let rx = match self.rx.take() {
            Some(rx) => rx,
            None => return,
        };
        let mut keep_rx = true;
        while let Ok(msg) = rx.try_recv() {
            match msg {
                WorkerMsg::Progress { current, total } => {
                    self.progress = if total > 0 {
                        current as f32 / total as f32
                    } else {
                        0.0
                    };
                    self.set_status(
                        &format!(
                            "计算中 {:.0}% | {}/{}",
                            self.progress * 100.0,
                            format::format_size(current),
                            format::format_size(total)
                        ),
                        false,
                    );
                }
                WorkerMsg::Done {
                    md5,
                    sha256,
                    elapsed_ms,
                } => {
                    self.md5_result = md5;
                    self.sha256_result = sha256;
                    self.elapsed_ms = elapsed_ms;
                    self.progress = 1.0;
                    self.update_result_text();
                    self.set_status(
                        &format!("计算完成 | 耗时 {:.1}秒", elapsed_ms as f64 / 1000.0),
                        false,
                    );
                    self.worker = None;
                    keep_rx = false;
                }
                WorkerMsg::Cancelled => {
                    self.set_status("已取消", false);
                    self.progress = 0.0;
                    self.worker = None;
                    keep_rx = false;
                }
                WorkerMsg::Error(e) => {
                    self.set_status(&format!("计算失败: {e}"), true);
                    self.progress = 0.0;
                    self.worker = None;
                    keep_rx = false;
                }
            }
        }
        if keep_rx {
            self.rx = Some(rx);
        }
    }
}

impl eframe::App for HashApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 先消费 worker 消息
        self.poll_worker();

        // 计算中持续请求重绘，确保进度条平滑
        if self.is_calculating() {
            ctx.request_repaint();
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            // === 文件选择区 ===
            ui.horizontal(|ui| {
                ui.label("文件路径:");
                ui.add(
                    TextEdit::singleline(&mut self.file_path)
                        .desired_width(480.0)
                        .hint_text("点击右侧浏览按钮选择文件"),
                );
                if ui.button("浏览...").clicked() && !self.is_calculating() {
                    self.pick_file();
                }
            });

            ui.separator();

            // === 哈希设置 ===
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.upper_case, "大写字母");
            });

            ui.separator();

            // === 计算结果 ===
            ui.label(RichText::new("计算结果").strong());
            ui.add(
                TextEdit::multiline(&mut self.result_text)
                    .desired_width(f32::INFINITY)
                    .desired_rows(6)
                    .font(egui::TextStyle::Monospace)
                    .interactive(false),
            );

            ui.horizontal(|ui| {
                if self.is_calculating() {
                    if ui.button("取消").clicked() {
                        self.cancel_calc();
                    }
                } else if ui.button("计算哈希").clicked() {
                    self.start_calc();
                }
                if ui.button("复制结果").clicked() && !self.is_calculating() {
                    self.copy_result();
                }
                if ui.button("清空").clicked() && !self.is_calculating() {
                    self.clear_all();
                }
            });

            ui.separator();

            // === 哈希验证 ===
            ui.label(RichText::new("哈希验证").strong());

            ui.horizontal(|ui| {
                ui.label("MD5:");
                ui.add(TextEdit::singleline(&mut self.md5_verify).desired_width(420.0));
                if let Some(ok) = self.md5_verify_ok() {
                    let (text, color) = if ok {
                        ("✓ 通过", Color32::GREEN)
                    } else {
                        ("✗ 失败", Color32::RED)
                    };
                    ui.label(RichText::new(text).color(color).strong());
                } else {
                    ui.label("-");
                }
            });

            ui.horizontal(|ui| {
                ui.label("SHA-256:");
                ui.add(TextEdit::singleline(&mut self.sha256_verify).desired_width(420.0));
                if let Some(ok) = self.sha256_verify_ok() {
                    let (text, color) = if ok {
                        ("✓ 通过", Color32::GREEN)
                    } else {
                        ("✗ 失败", Color32::RED)
                    };
                    ui.label(RichText::new(text).color(color).strong());
                } else {
                    ui.label("-");
                }
            });

            if ui.button("验证").clicked() && !self.is_calculating() {
                self.verify();
            }

            ui.separator();

            // === 状态栏 + 进度条 ===
            let color = if self.status_error {
                Color32::RED
            } else {
                Color32::GREEN
            };
            ui.label(RichText::new(&self.status).color(color));
            ui.add(egui::ProgressBar::new(self.progress));
        });
    }
}
