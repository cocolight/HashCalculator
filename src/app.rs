//! egui 主应用：「单文件」与「批量」两个标签页。
//!
//! - 单文件页：文件选择、哈希设置、计算结果、哈希验证、状态栏 + 进度条。
//! - 批量页：多选文件 / 选文件夹（非递归）→ 顺序计算 → 虚拟化表格 → 导出与复制。
//!
//! 两个页面的计算都走同一条 `worker::hash_file` 路径，避免出现会漂移的第二套实现。

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::SystemTime;

use egui::{Color32, RichText, TextEdit};

use crate::batch::{self, BatchHandle, BatchItem, BatchMsg};
use crate::format;
use crate::worker::{self, WorkerHandle, WorkerMsg};

/// 顶部标签页。
#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Single,
    Batch,
}

/// 批量列表中一行的状态。
#[derive(Clone, PartialEq)]
enum RowStatus {
    Pending,
    Running,
    Done,
    Error(String),
    Cancelled,
}

impl RowStatus {
    /// 是否为终态（不会再被后台线程更新）。
    fn is_terminal(&self) -> bool {
        !matches!(self, RowStatus::Pending | RowStatus::Running)
    }

    /// 表格中显示的文案与颜色。
    fn display(&self) -> (String, Color32) {
        match self {
            RowStatus::Pending => ("待计算".to_string(), Color32::GRAY),
            RowStatus::Running => ("计算中".to_string(), Color32::LIGHT_BLUE),
            RowStatus::Done => ("完成".to_string(), Color32::GREEN),
            RowStatus::Cancelled => ("已取消".to_string(), Color32::GRAY),
            RowStatus::Error(e) => (format!("失败: {e}"), Color32::RED),
        }
    }
}

/// 批量列表中的一行。
struct BatchRow {
    path: PathBuf,
    name: String,
    path_display: String,
    size: u64,
    status: RowStatus,
    md5: String,
    sha256: String,
    elapsed_ms: u128,
    selected: bool,
}

/// 批量页的全部状态。
struct BatchState {
    rows: Vec<BatchRow>,
    /// 已加入过的路径（canonicalize 后的键），用于去重。
    seen: HashSet<PathBuf>,
    /// 批量消息里的下标 → `rows` 下标；每轮「开始」时按只提交未完成行重建。
    index_map: Vec<usize>,
    /// 当前正在计算的行下标。
    current: Option<usize>,
    /// 当前文件的进度（0..=1）。
    file_progress: f32,
    running: bool,
    status: String,
    status_error: bool,
    handle: Option<BatchHandle>,
    rx: Option<Receiver<BatchMsg>>,
}

impl BatchState {
    fn new() -> Self {
        Self {
            rows: Vec::new(),
            seen: HashSet::new(),
            index_map: Vec::new(),
            current: None,
            file_progress: 0.0,
            running: false,
            status: "就绪".into(),
            status_error: false,
            handle: None,
            rx: None,
        }
    }

    fn set_status(&mut self, msg: &str, err: bool) {
        self.status = msg.into();
        self.status_error = err;
    }

    /// 已完成（处于终态）的行数。
    fn terminal_count(&self) -> usize {
        self.rows.iter().filter(|r| r.status.is_terminal()).count()
    }

    /// 整批进度（0..=1）：已完成行数 + 当前文件进度。
    fn overall_progress(&self) -> f32 {
        let n = self.rows.len();
        if n == 0 {
            return 0.0;
        }
        let cur = if self.running { self.file_progress } else { 0.0 };
        ((self.terminal_count() as f32 + cur) / n as f32).clamp(0.0, 1.0)
    }
}

pub struct HashApp {
    tab: Tab,

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

    batch: BatchState,
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
            fonts
                .font_data
                .insert(name.clone(), egui::FontData::from_owned(bytes).into());
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
            tab: Tab::Single,
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
            batch: BatchState::new(),
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

    // ==================== 批量页 ====================

    /// 多选文件加入列表（自动去重）。
    fn batch_add_files(&mut self) {
        let Some(paths) = rfd::FileDialog::new()
            .set_title("选择文件（可多选）")
            .pick_files()
        else {
            return;
        };
        let mut added = 0usize;
        let mut dup = 0usize;
        for p in paths {
            if self.batch_push_path(p) {
                added += 1;
            } else {
                dup += 1;
            }
        }
        let msg = if dup > 0 {
            format!("已添加 {added} 个文件（{dup} 个重复已忽略）")
        } else {
            format!("已添加 {added} 个文件")
        };
        self.batch.set_status(&msg, false);
    }

    /// 选文件夹加入列表：**不递归**，只收该层的直接文件。
    fn batch_add_folder(&mut self) {
        let Some(dir) = rfd::FileDialog::new()
            .set_title("选择文件夹（不含子目录）")
            .pick_folder()
        else {
            return;
        };

        let mut files: Vec<PathBuf> = Vec::new();
        let mut subdirs = 0usize;
        let mut unreadable = 0usize;
        match std::fs::read_dir(&dir) {
            Ok(entries) => {
                for e in entries.flatten() {
                    match e.file_type() {
                        Ok(ft) if ft.is_file() => files.push(e.path()),
                        Ok(ft) if ft.is_dir() => subdirs += 1,
                        _ => unreadable += 1,
                    }
                }
            }
            Err(e) => {
                self.batch.set_status(&format!("无法读取文件夹: {e}"), true);
                return;
            }
        }

        files.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

        let mut added = 0usize;
        let mut dup = 0usize;
        for p in files {
            if self.batch_push_path(p) {
                added += 1;
            } else {
                dup += 1;
            }
        }

        let mut msg = format!("已添加 {added} 个文件（仅直接文件，不含子目录");
        if subdirs > 0 {
            msg.push_str(&format!("；已跳过 {subdirs} 个子目录"));
        }
        if dup > 0 {
            msg.push_str(&format!("；{dup} 个重复已忽略"));
        }
        if unreadable > 0 {
            msg.push_str(&format!("；{unreadable} 项无法识别"));
        }
        msg.push('）');
        self.batch.set_status(&msg, false);
    }

    /// 把一个路径加入批量列表；返回是否真的加入（重复返回 false）。
    fn batch_push_path(&mut self, path: PathBuf) -> bool {
        let key = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if !self.batch.seen.insert(key) {
            return false;
        }
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let path_display = path.to_string_lossy().to_string();
        self.batch.rows.push(BatchRow {
            path,
            name,
            path_display,
            size,
            status: RowStatus::Pending,
            md5: String::new(),
            sha256: String::new(),
            elapsed_ms: 0,
            selected: false,
        });
        true
    }

    fn batch_clear(&mut self) {
        if self.batch.running {
            self.batch_cancel();
            return;
        }
        self.batch.rows.clear();
        self.batch.seen.clear();
        self.batch.index_map.clear();
        self.batch.current = None;
        self.batch.file_progress = 0.0;
        self.batch.set_status("就绪", false);
    }

    /// 开始批量计算。只提交**尚未完成**的行，因此取消后可再次「开始」续算。
    fn batch_start(&mut self) {
        if self.batch.running {
            return;
        }
        if self.batch.rows.is_empty() {
            self.batch.set_status("列表为空，请先添加文件", true);
            return;
        }

        let targets: Vec<usize> = self
            .batch
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| r.status != RowStatus::Done)
            .map(|(i, _)| i)
            .collect();
        if targets.is_empty() {
            self.batch.set_status("全部文件均已完成", false);
            return;
        }

        let items: Vec<BatchItem> = targets
            .iter()
            .map(|&i| BatchItem {
                path: self.batch.rows[i].path.clone(),
                size: self.batch.rows[i].size,
            })
            .collect();

        for &i in &targets {
            let r = &mut self.batch.rows[i];
            r.status = RowStatus::Pending;
            r.md5.clear();
            r.sha256.clear();
            r.elapsed_ms = 0;
        }

        let (handle, rx) = batch::spawn_batch(items, self.upper_case);
        self.batch.index_map = targets;
        self.batch.handle = Some(handle);
        self.batch.rx = Some(rx);
        self.batch.running = true;
        self.batch.current = None;
        self.batch.file_progress = 0.0;
        self.batch.set_status("开始批量计算...", false);
    }

    fn batch_cancel(&mut self) {
        if let Some(h) = &self.batch.handle {
            h.cancel();
            self.batch.set_status("正在取消...", false);
        }
    }

    /// 消费批量线程消息（与 `poll_worker` 相同的 take 手法，规避借用冲突）。
    fn poll_batch(&mut self) {
        let rx = match self.batch.rx.take() {
            Some(rx) => rx,
            None => return,
        };
        let mut keep_rx = true;
        while let Ok(msg) = rx.try_recv() {
            match msg {
                BatchMsg::FileStarted { index, size } => {
                    if let Some(&row_i) = self.batch.index_map.get(index) {
                        let name = {
                            let r = &mut self.batch.rows[row_i];
                            r.status = RowStatus::Running;
                            r.size = size;
                            r.name.clone()
                        };
                        self.batch.current = Some(row_i);
                        self.batch.file_progress = 0.0;
                        self.batch.set_status(&format!("计算中：{name}"), false);
                    }
                }
                BatchMsg::FileProgress {
                    index,
                    current,
                    total,
                } => {
                    if let Some(&row_i) = self.batch.index_map.get(index) {
                        let name = self.batch.rows[row_i].name.clone();
                        let frac = if total > 0 {
                            current as f32 / total as f32
                        } else {
                            0.0
                        };
                        self.batch.file_progress = frac;
                        self.batch.set_status(
                            &format!(
                                "计算中 {:.0}% | {} | {}/{}",
                                frac * 100.0,
                                name,
                                format::format_size(current),
                                format::format_size(total)
                            ),
                            false,
                        );
                    }
                }
                BatchMsg::FileDone {
                    index,
                    md5,
                    sha256,
                    elapsed_ms,
                } => {
                    if let Some(&row_i) = self.batch.index_map.get(index) {
                        let r = &mut self.batch.rows[row_i];
                        r.md5 = md5;
                        r.sha256 = sha256;
                        r.elapsed_ms = elapsed_ms;
                        r.status = RowStatus::Done;
                    }
                    self.batch.file_progress = 1.0;
                }
                BatchMsg::FileError { index, error } => {
                    if let Some(&row_i) = self.batch.index_map.get(index) {
                        self.batch.rows[row_i].status = RowStatus::Error(error);
                    }
                    self.batch.file_progress = 0.0;
                }
                BatchMsg::FileCancelled { index } => {
                    if let Some(&row_i) = self.batch.index_map.get(index) {
                        self.batch.rows[row_i].status = RowStatus::Cancelled;
                    }
                    self.batch.file_progress = 0.0;
                }
                BatchMsg::AllDone {
                    done,
                    failed,
                    cancelled,
                    elapsed_ms,
                } => {
                    self.batch.running = false;
                    self.batch.handle = None;
                    self.batch.current = None;
                    self.batch.file_progress = 0.0;
                    keep_rx = false;
                    let msg = if cancelled {
                        format!("已取消 | 本次完成 {done} 个，失败 {failed} 个")
                    } else {
                        format!(
                            "批量完成 | 成功 {done} 个，失败 {failed} 个 | 耗时 {:.1}秒",
                            elapsed_ms as f64 / 1000.0
                        )
                    };
                    self.batch.set_status(&msg, failed > 0);
                }
            }
        }
        if keep_rx {
            self.batch.rx = Some(rx);
        }
    }

    /// 单文件页。
    fn ui_single(&mut self, ui: &mut egui::Ui) {
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
    }

    /// 批量页。
    fn ui_batch(&mut self, ui: &mut egui::Ui) {
        let idle = !self.batch.running;
        let n = self.batch.rows.len();
        let selected = self.batch.rows.iter().filter(|r| r.selected).count();

        // === 来源与运行控制 ===
        ui.horizontal(|ui| {
            if ui
                .add_enabled(idle, egui::Button::new("添加文件"))
                .on_hover_text("可多选")
                .clicked()
            {
                self.batch_add_files();
            }
            if ui
                .add_enabled(idle, egui::Button::new("添加文件夹"))
                .on_hover_text("只收该层直接文件，不含子目录")
                .clicked()
            {
                self.batch_add_folder();
            }
            if ui.add_enabled(idle, egui::Button::new("清空")).clicked() {
                self.batch_clear();
            }
            ui.separator();
            if self.batch.running {
                if ui.button("取消").clicked() {
                    self.batch_cancel();
                }
            } else if ui
                .add_enabled(!self.batch.rows.is_empty(), egui::Button::new("开始计算"))
                .clicked()
            {
                self.batch_start();
            }
            ui.separator();
            ui.checkbox(&mut self.upper_case, "大写字母");
        });

        ui.separator();

        // === 结果表格（虚拟化：只渲染可见行）===
        if n == 0 {
            ui.add_space(6.0);
            ui.label("列表为空：点击「添加文件」或「添加文件夹」加入待计算文件。");
        } else {
            let row_h = ui
                .spacing()
                .interact_size
                .y
                .max(ui.text_style_height(&egui::TextStyle::Body));

            // 表头也占一行，故总行数为 n + 1；两者共用同一套行号，striped 才能对齐
            let table_h = (ui.available_height() - 78.0).max(100.0);
            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .max_height(table_h)
                .show_rows(ui, row_h, n + 1, |ui, range| {
                    egui::Grid::new("batch_grid")
                        .striped(true)
                        .start_row(range.start)
                        .spacing([10.0, 4.0])
                        .show(ui, |ui| {
                            for row in range {
                                if row == 0 {
                                    for h in [
                                        "选", "文件名", "路径", "大小", "MD5", "SHA-256", "状态", "耗时",
                                    ] {
                                        ui.label(RichText::new(h).strong());
                                    }
                                    ui.end_row();
                                    continue;
                                }

                                let r = &mut self.batch.rows[row - 1];
                                ui.checkbox(&mut r.selected, "");
                                ui.add_sized(
                                    [180.0, row_h],
                                    egui::Label::new(RichText::new(&r.name)).truncate(),
                                );
                                ui.add_sized(
                                    [220.0, row_h],
                                    egui::Label::new(RichText::new(&r.path_display).weak())
                                        .truncate(),
                                );
                                ui.label(format::format_size(r.size));
                                ui.label(
                                    RichText::new(if r.md5.is_empty() { "-" } else { &r.md5 })
                                        .monospace(),
                                );
                                ui.label(
                                    RichText::new(if r.sha256.is_empty() {
                                        "-"
                                    } else {
                                        &r.sha256
                                    })
                                    .monospace(),
                                );
                                let (text, color) = r.status.display();
                                ui.add_sized(
                                    [140.0, row_h],
                                    egui::Label::new(RichText::new(text).color(color)).truncate(),
                                );
                                ui.label(if r.elapsed_ms == 0 {
                                    "-".to_string()
                                } else {
                                    format!("{} ms", r.elapsed_ms)
                                });
                                ui.end_row();
                            }
                        });
                });
        }

        ui.separator();

        // === 进度与状态 ===
        ui.horizontal(|ui| {
            ui.label(format!(
                "共 {n} 个文件 | 已完成 {} | 已勾选 {selected}",
                self.batch.terminal_count()
            ));
        });
        ui.add(
            egui::ProgressBar::new(self.batch.overall_progress())
                .show_percentage()
                .desired_width(f32::INFINITY),
        );
        if self.batch.running {
            let cur = self
                .batch
                .current
                .and_then(|i| self.batch.rows.get(i))
                .map(|r| r.name.clone())
                .unwrap_or_default();
            ui.add(
                egui::ProgressBar::new(self.batch.file_progress)
                    .text(if cur.is_empty() {
                        "当前文件".to_string()
                    } else {
                        format!("当前文件：{cur}")
                    })
                    .desired_width(f32::INFINITY),
            );
        }
        let color = if self.batch.status_error {
            Color32::RED
        } else {
            Color32::GREEN
        };
        ui.label(RichText::new(&self.batch.status).color(color));
    }
}

impl eframe::App for HashApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 先消费两条后台线程的消息
        self.poll_worker();
        self.poll_batch();

        // 计算中持续请求重绘，确保进度条平滑
        if self.is_calculating() || self.batch.running {
            ctx.request_repaint();
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Single, "单文件");
                ui.selectable_value(&mut self.tab, Tab::Batch, "批量");
            });
            ui.separator();

            match self.tab {
                Tab::Single => self.ui_single(ui),
                Tab::Batch => self.ui_batch(ui),
            }
        });
    }
}
