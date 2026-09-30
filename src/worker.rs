//! 后台哈希计算工作线程：内存映射文件 + MD5/SHA-256 并行计算，
//! 通过 channel 向 UI 线程推送进度与结果，支持取消。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::Sender, Arc};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use egui::Context;
use md5::Digest;
use memmap2::Mmap;

/// 工作线程发送给 UI 线程的消息。
pub enum WorkerMsg {
    Progress { current: u64, total: u64 },
    Done {
        md5: String,
        sha256: String,
        elapsed_ms: u128,
    },
    Error(String),
    Cancelled,
}

/// 对计算任务的句柄，可发送取消信号。
pub struct WorkerHandle {
    cancel: Arc<AtomicBool>,
}

impl WorkerHandle {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

enum WorkerError {
    Cancelled,
    Other(String),
}

impl From<std::io::Error> for WorkerError {
    fn from(e: std::io::Error) -> Self {
        WorkerError::Other(e.to_string())
    }
}

/// 启动后台哈希计算线程，返回 (取消句柄, 消息接收端)。
pub fn spawn(
    path: PathBuf,
    upper: bool,
    ctx: Context,
) -> (WorkerHandle, mpsc::Receiver<WorkerMsg>) {
    let (tx, rx) = mpsc::channel::<WorkerMsg>();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();
    let ctx_clone = ctx.clone();

    thread::spawn(move || {
        let result = compute(&path, upper, &cancel_clone, &ctx_clone, &tx);
        let msg = match result {
            Ok((md5, sha256, elapsed_ms)) => WorkerMsg::Done {
                md5,
                sha256,
                elapsed_ms,
            },
            Err(WorkerError::Cancelled) => WorkerMsg::Cancelled,
            Err(WorkerError::Other(e)) => WorkerMsg::Error(e),
        };
        let _ = tx.send(msg);
        ctx.request_repaint();
    });

    (WorkerHandle { cancel }, rx)
}

fn compute(
    path: &Path,
    upper: bool,
    cancel: &AtomicBool,
    ctx: &Context,
    tx: &Sender<WorkerMsg>,
) -> Result<(String, String, u128), WorkerError> {
    let start = Instant::now();

    let file = std::fs::File::open(path)?;
    let total = file.metadata()?.len();
    if total == 0 {
        return Err(WorkerError::Other("文件为空".into()));
    }

    // 跨平台内存映射文件（Windows: CreateFileMapping; Linux/macOS: mmap）
    let mmap = unsafe { Mmap::map(&file) }?;

    let mut md5 = md5::Md5::new();
    let mut sha256 = sha2::Sha256::new();

    const CHUNK_SIZE: usize = 64 * 1024 * 1024; // 64MB 视图，减少映射/分块开销
    const UPDATE_INTERVAL: u64 = 256 * 1024 * 1024; // 每 256MB 更新一次进度

    let mut current: u64 = 0;
    let mut last_update: u64 = 0;

    // 初始进度
    let _ = tx.send(WorkerMsg::Progress {
        current: 0,
        total,
    });
    ctx.request_repaint();

    for chunk in mmap.chunks(CHUNK_SIZE) {
        if cancel.load(Ordering::Relaxed) {
            return Err(WorkerError::Cancelled);
        }
        md5.update(chunk);
        sha256.update(chunk);
        current += chunk.len() as u64;

        if current - last_update >= UPDATE_INTERVAL || current >= total {
            let _ = tx.send(WorkerMsg::Progress { current, total });
            ctx.request_repaint();
            last_update = current;
        }
    }

    // 循环结束后再检查一次取消
    if cancel.load(Ordering::Relaxed) {
        return Err(WorkerError::Cancelled);
    }

    let md5_hex = hex::encode(md5.finalize());
    let sha256_hex = hex::encode(sha256.finalize());

    let md5_result = if upper {
        md5_hex.to_uppercase()
    } else {
        md5_hex
    };
    let sha256_result = if upper {
        sha256_hex.to_uppercase()
    } else {
        sha256_hex
    };

    let elapsed_ms = start.elapsed().as_millis();
    Ok((md5_result, sha256_result, elapsed_ms))
}
