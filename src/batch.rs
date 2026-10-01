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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 顺序批量跑真实 worker 路径：结果必须与单文件路径一致。
    #[test]
    fn batch_matches_single_file_path() {
        let mut paths = Vec::new();
        for (tag, bytes) in [("b0", &b""[..]), ("b1", b"hello"), ("b2", b"world!")] {
            let mut p = std::env::temp_dir();
            p.push(format!("hash_calculator_batch_{}_{tag}", std::process::id()));
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
                    index,
                    md5,
                    sha256,
                    ..
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
            assert_eq!(results[i].2, exp_sha, "第 {i} 行 SHA-256 与单文件路径不一致");
            let _ = std::fs::remove_file(path);
        }
    }
}
