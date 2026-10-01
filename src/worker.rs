//! 后台哈希计算工作线程：内存映射文件 + MD5/SHA-256 计算，
//! 通过 channel 向 UI 线程推送进度与结果，支持取消。
//!
//! 本模块不依赖 egui：UI 侧在计算期间每帧 `request_repaint()`，进度消息由
//! `app::HashApp::poll_worker` 在主线程消费，因此工作线程无需（也不应）触碰 ctx。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use md5::Digest;
use memmap2::Mmap;

/// 进度推送节流：最多约 10 次/秒，避免 UI 线程被消息淹没。
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// 处理粒度：既决定循环开销，也决定「取消」的响应延迟上限。
const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB

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
pub fn spawn(path: PathBuf, upper: bool) -> (WorkerHandle, mpsc::Receiver<WorkerMsg>) {
    let (tx, rx) = mpsc::channel::<WorkerMsg>();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();

    thread::spawn(move || {
        let result = compute(&path, upper, &cancel_clone, &tx);
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
    });

    (WorkerHandle { cancel }, rx)
}

fn compute(
    path: &Path,
    upper: bool,
    cancel: &AtomicBool,
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

    let mut current: u64 = 0;
    let mut last_update = Instant::now();

    // 初始进度
    let _ = tx.send(WorkerMsg::Progress { current: 0, total });

    for chunk in mmap.chunks(CHUNK_SIZE) {
        if cancel.load(Ordering::Relaxed) {
            return Err(WorkerError::Cancelled);
        }
        md5.update(chunk);
        sha256.update(chunk);
        current += chunk.len() as u64;

        // 按时间节流：保证进度连续，又不因小文件频繁发送
        if last_update.elapsed() >= PROGRESS_INTERVAL || current >= total {
            let _ = tx.send(WorkerMsg::Progress { current, total });
            last_update = Instant::now();
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
