//! 批量哈希：后台**单线程顺序**遍历文件列表，逐个复用 `worker::hash_file`。
//!
//! 设计要点：
//! - **顺序执行**：单个文件内部已用双线程并行 MD5/SHA-256，若再对 N 个文件并发，
//!   会变成 2N 个线程争抢 CPU 与页缓存，进度与取消语义急剧复杂化，收益却有限。
//! - **单文件失败不中断整批**：某行报错后继续处理后续文件。
//! - **取消两层生效**：文件之间在循环开头检查；文件内部复用 `hash_file` 的 4MB 块粒度检查。
//! - 本模块**不依赖 egui**，可独立单元测试。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use crate::worker::{self, HashError};

/// 批量列表中的一项（进入计算前的静态信息）。
pub struct BatchItem {
    pub path: PathBuf,
    pub size: u64,
}

/// 批量线程发送给 UI 线程的消息。
pub enum BatchMsg {
    FileStarted {
        index: usize,
        size: u64,
    },
    FileProgress {
        index: usize,
        current: u64,
        total: u64,
    },
    FileDone {
        index: usize,
        md5: String,
        sha256: String,
        elapsed_ms: u128,
    },
    FileError {
        index: usize,
        error: String,
    },
    FileCancelled {
        index: usize,
    },
    /// 整批结束；`done` 为成功数，`failed` 为失败数，`cancelled` 表示被取消。
    AllDone {
        done: usize,
        failed: usize,
        cancelled: bool,
        elapsed_ms: u128,
    },
}

/// 对批量任务的句柄，可发送取消信号。
pub struct BatchHandle {
    cancel: Arc<AtomicBool>,
}

impl BatchHandle {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// 启动后台批量计算线程，返回 (取消句柄, 消息接收端)。
///
/// 顺序遍历 `items`：每轮开头检查取消；单个文件失败或取消都不影响已完成的行的结果。
pub fn spawn_batch(items: Vec<BatchItem>, upper: bool) -> (BatchHandle, mpsc::Receiver<BatchMsg>) {
    let (tx, rx) = mpsc::channel::<BatchMsg>();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();

    thread::spawn(move || {
        let start = Instant::now();
        let mut done = 0usize;
        let mut failed = 0usize;
        let mut cancelled = false;

        for (index, item) in items.iter().enumerate() {
            // 文件之间检查取消
            if cancel_clone.load(Ordering::Relaxed) {
                cancelled = true;
                break;
            }

            let _ = tx.send(BatchMsg::FileStarted {
                index,
                size: item.size,
            });

            // 进度回调借用 tx，作用域结束后再发送终态消息
            let msg = {
                let mut on_progress = |current: u64, total: u64| {
                    let _ = tx.send(BatchMsg::FileProgress {
                        index,
                        current,
                        total,
                    });
                };
                match worker::hash_file(&item.path, upper, &cancel_clone, &mut on_progress) {
                    Ok(o) => BatchMsg::FileDone {
                        index,
                        md5: o.md5,
                        sha256: o.sha256,
                        elapsed_ms: o.elapsed_ms,
                    },
                    Err(HashError::Cancelled) => BatchMsg::FileCancelled { index },
                    Err(HashError::Other(e)) => BatchMsg::FileError { index, error: e },
                }
            };

            let is_cancelled = matches!(msg, BatchMsg::FileCancelled { .. });
            let is_error = matches!(msg, BatchMsg::FileError { .. });
            let _ = tx.send(msg);

            if is_cancelled {
                cancelled = true;
                break;
            }
            if is_error {
                failed += 1;
            } else {
                done += 1;
            }
        }

        let _ = tx.send(BatchMsg::AllDone {
            done,
            failed,
            cancelled,
            elapsed_ms: start.elapsed().as_millis(),
        });
    });

    (BatchHandle { cancel }, rx)
}

/// 从一组勾选状态里挑出要处理的行下标。
///
/// 规则：**只要有任意一行被勾选，就只处理勾选的行；否则处理全部行。**
/// 计算与导出/复制共用这一条规则，集中在此以免两处实现各自漂移。
pub fn pick_indices(selected: &[bool]) -> Vec<usize> {
    let any_selected = selected.iter().any(|&s| s);
    selected
        .iter()
        .enumerate()
        .filter(|(_, &s)| !any_selected || s)
        .map(|(i, _)| i)
        .collect()
}

/// 导出用的一行（与 UI 状态解耦，便于本模块独立测试）。
pub struct ExportRow {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub md5: String,
    pub sha256: String,
    pub status: String,
    pub elapsed_ms: u128,
}

/// 按 RFC 4180 转义单个 CSV 字段：字段含逗号、双引号、换行或回车时，
/// 用双引号包裹，并把内部的双引号翻倍。
pub fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// 生成 CSV 文本：UTF-8 BOM + CRLF 行尾。
///
/// BOM 是必需的 —— 否则 Excel 打开含中文路径的 CSV 会按本地代码页解码而乱码。
pub fn to_csv(rows: &[ExportRow]) -> String {
    let mut out = String::from("\u{feff}");
    out.push_str("file_name,path,size_bytes,md5,sha256,status,elapsed_ms\r\n");
    for r in rows {
        let cols = [
            csv_field(&r.name),
            csv_field(&r.path),
            r.size.to_string(),
            csv_field(&r.md5),
            csv_field(&r.sha256),
            csv_field(&r.status),
            r.elapsed_ms.to_string(),
        ];
        out.push_str(&cols.join(","));
        out.push_str("\r\n");
    }
    out
}

/// 生成便于阅读的 TXT 文本（每文件一段）。
pub fn to_txt(rows: &[ExportRow]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for r in rows {
        let _ = writeln!(out, "文件: {}", r.name);
        let _ = writeln!(out, "路径: {}", r.path);
        let _ = writeln!(out, "大小: {} 字节", r.size);
        let _ = writeln!(out, "MD5: {}", dash_if_empty(&r.md5));
        let _ = writeln!(out, "SHA-256: {}", dash_if_empty(&r.sha256));
        let _ = writeln!(out, "状态: {}", r.status);
        let _ = writeln!(out, "耗时: {} ms", r.elapsed_ms);
        let _ = writeln!(out);
    }
    out
}

/// 生成 TSV 文本，供「复制选中」写入剪贴板后直接粘进表格软件。
pub fn to_tsv(rows: &[ExportRow]) -> String {
    use std::fmt::Write;
    let mut out = String::from("文件名\t路径\t大小\tMD5\tSHA-256\t状态\n");
    for r in rows {
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}",
            r.name,
            r.path,
            r.size,
            dash_if_empty(&r.md5),
            dash_if_empty(&r.sha256),
            r.status
        );
    }
    out
}

fn dash_if_empty(s: &str) -> &str {
    if s.is_empty() {
        "-"
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn pick_indices_prefers_selection_when_any_row_is_checked() {
        assert_eq!(pick_indices(&[]), Vec::<usize>::new());
        // 一个都没勾 → 全部行
        assert_eq!(pick_indices(&[false, false]), vec![0, 1]);
        // 只要勾了一个 → 只取勾选的
        assert_eq!(pick_indices(&[true, false, true]), vec![0, 2]);
        assert_eq!(pick_indices(&[false, true]), vec![1]);
    }

    #[test]
    fn csv_field_passes_through_plain_text() {
        assert_eq!(csv_field("abc"), "abc");
        assert_eq!(csv_field(""), "");
    }

    #[test]
    fn csv_field_quotes_special_characters() {
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("a\nb"), "\"a\nb\"");
        assert_eq!(csv_field("a\r\nb"), "\"a\r\nb\"");
        // 中文路径无需转义
        assert_eq!(csv_field("C:\\中文 目录\\a.txt"), "C:\\中文 目录\\a.txt");
    }

    fn sample_row() -> ExportRow {
        ExportRow {
            name: "a,b\"c.txt".into(),
            path: "C:\\tmp\\a,b\".txt".into(),
            size: 12,
            md5: "D41D8CD98F00B204E9800998ECF8427E".into(),
            sha256: "ABC".into(),
            status: "完成".into(),
            elapsed_ms: 7,
        }
    }

    #[test]
    fn csv_has_bom_crlf_and_escaped_fields() {
        let csv = to_csv(&[sample_row()]);
        assert!(csv.starts_with('\u{feff}'), "CSV 必须带 UTF-8 BOM");
        assert!(csv.contains("\r\n"), "CSV 必须用 CRLF 行尾");
        assert!(csv.contains("\"a,b\"\"c.txt\""), "文件名需按 RFC 4180 转义");
        assert_eq!(csv.matches("\r\n").count(), 2, "1 行表头 + 1 行数据");
    }

    #[test]
    fn txt_and_tsv_report_each_file() {
        let rows = [ExportRow {
            name: "x.bin".into(),
            path: "/tmp/x.bin".into(),
            size: 3,
            md5: "M".into(),
            sha256: String::new(),
            status: "完成".into(),
            elapsed_ms: 1,
        }];
        let txt = to_txt(&rows);
        assert!(txt.contains("文件: x.bin"));
        assert!(txt.contains("MD5: M"));
        assert!(txt.contains("SHA-256: -"), "空哈希应显示为连字符");

        let tsv = to_tsv(&rows);
        assert!(tsv.starts_with("文件名\t路径\t"));
        assert!(tsv.contains("x.bin\t/tmp/x.bin\t3\tM\t-"));
    }

    /// 顺序批量跑真实 worker 路径：结果必须与单文件路径一致。
    #[test]
    fn batch_matches_single_file_path() {
        let mut paths = Vec::new();
        for (tag, bytes) in [("b0", &b""[..]), ("b1", b"hello"), ("b2", b"world!")] {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "hash_calculator_batch_{}_{tag}",
                std::process::id()
            ));
            let mut f = std::fs::File::create(&p).expect("create temp file");
            f.write_all(bytes).expect("write temp file");
            f.flush().expect("flush");
            paths.push(p);
        }

        let items: Vec<BatchItem> = paths
            .iter()
            .map(|p| BatchItem {
                path: p.clone(),
                size: std::fs::metadata(p).unwrap().len(),
            })
            .collect();

        let (_handle, rx) = spawn_batch(items, false);
        let mut results: Vec<(usize, String, String)> = Vec::new();
        let mut all_done = false;
        while let Ok(msg) = rx.recv() {
            match msg {
                BatchMsg::FileDone {
                    index, md5, sha256, ..
                } => results.push((index, md5, sha256)),
                BatchMsg::AllDone {
                    done,
                    failed,
                    cancelled,
                    ..
                } => {
                    assert_eq!((done, failed, cancelled), (3, 0, false));
                    all_done = true;
                    break;
                }
                BatchMsg::FileError { error, .. } => panic!("unexpected error: {error}"),
                _ => {}
            }
        }
        assert!(all_done, "批量未正常结束");
        results.sort_by_key(|(i, _, _)| *i);

        // 与单文件路径逐个比对
        for (i, path) in paths.iter().enumerate() {
            let (_h, single_rx) = worker::spawn(path.clone(), false);
            let (exp_md5, exp_sha) = loop {
                match single_rx.recv().expect("single worker closed") {
                    worker::WorkerMsg::Done { md5, sha256, .. } => break (md5, sha256),
                    worker::WorkerMsg::Error(e) => panic!("single error: {e}"),
                    worker::WorkerMsg::Cancelled => panic!("single cancelled"),
                    _ => {}
                }
            };
            assert_eq!(results[i].1, exp_md5, "第 {i} 行 MD5 与单文件路径不一致");
            assert_eq!(
                results[i].2, exp_sha,
                "第 {i} 行 SHA-256 与单文件路径不一致"
            );
            let _ = std::fs::remove_file(path);
        }
    }

    /// 取消应立刻生效，且已完成的文件结果不被破坏。
    ///
    /// 首个文件刻意做大（16MB，约 30ms）——取消紧跟 `spawn_batch` 之后发出，
    /// 必然落在它的计算过程中，因此本用例不依赖精细的时序。
    #[test]
    fn cancel_stops_the_batch_immediately() {
        let mut paths = Vec::new();
        for (tag, bytes) in [
            ("c_big", vec![0u8; 16 * 1024 * 1024]),
            ("c_small", b"tail".to_vec()),
        ] {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "hash_calculator_cancel_{}_{tag}",
                std::process::id()
            ));
            let mut f = std::fs::File::create(&p).expect("create temp file");
            f.write_all(&bytes).expect("write temp file");
            f.flush().expect("flush");
            paths.push(p);
        }

        let items: Vec<BatchItem> = paths
            .iter()
            .map(|p| BatchItem {
                path: p.clone(),
                size: std::fs::metadata(p).unwrap().len(),
            })
            .collect();

        let (handle, rx) = spawn_batch(items, false);
        handle.cancel();

        let mut done_rows = 0usize;
        let mut all_done = false;
        while let Ok(msg) = rx.recv() {
            match msg {
                BatchMsg::FileDone { .. } => done_rows += 1,
                BatchMsg::AllDone {
                    done,
                    failed,
                    cancelled,
                    ..
                } => {
                    assert!(cancelled, "取消信号应使整批标记为 cancelled");
                    assert_eq!((done, failed), (0, 0), "首个文件尚未完成就已被取消");
                    assert_eq!(done_rows, 0, "不应有文件被报告为完成");
                    all_done = true;
                    break;
                }
                _ => {}
            }
        }
        assert!(all_done, "批量未正常结束");

        for p in &paths {
            let _ = std::fs::remove_file(p);
        }
    }
}
