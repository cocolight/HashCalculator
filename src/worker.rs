//! 后台哈希计算工作线程：内存映射文件 + MD5/SHA-256 计算，
//! 通过 channel 向 UI 线程推送进度与结果，支持取消。
//!
//! 本模块不依赖 egui：UI 侧在计算期间每帧 `request_repaint()`，进度消息由
//! `app::HashApp::poll_worker` 在主线程消费，因此工作线程无需（也不应）触碰 ctx。
//!
//! 加速策略：单文件是 Merkle–Damgård 链，块与块之间必须顺序计算，无法按块并行；
//! 唯一可并行的是**两个互相独立的算法** —— MD5 与 SHA-256 各占一核，两线程各自
//! 遍历同一块 mmap（零拷贝），总耗时 ≈ max(MD5, SHA-256)。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// 协调线程的轮询间隔：决定「一侧算法完工」后多久被察觉。
/// 必须远小于 PROGRESS_INTERVAL，否则小文件会被节流间隔拖慢。
const POLL_INTERVAL: Duration = Duration::from_millis(2);

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

    // 跨平台内存映射文件（Windows: CreateFileMapping; Linux/macOS: mmap）
    // 0 字节文件同样可映射：memmap2 在 Windows 上对长度为 0 的情况不会调用
    // CreateFileMappingW（该调用会返回 ERROR_FILE_INVALID），而是直接给出空切片。
    let mmap = unsafe { Mmap::map(&file) }?;

    // 初始进度
    let _ = tx.send(WorkerMsg::Progress { current: 0, total });

    let (md5_hex, sha256_hex) = hash_parallel(&mmap, total, cancel, tx)?;

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

/// 双线程并行：MD5 与 SHA-256 各自遍历同一份 mmap，各占一核。
fn hash_parallel(
    mmap: &[u8],
    total: u64,
    cancel: &AtomicBool,
    tx: &Sender<WorkerMsg>,
) -> Result<(String, String), WorkerError> {
    let md5_done = AtomicU64::new(0);
    let sha_done = AtomicU64::new(0);

    let (md5_ok, sha_ok, md5_hex, sha_hex) = thread::scope(|scope| {
        let h_md5 = scope.spawn(|| {
            let mut h = md5::Md5::new();
            let ok = hash_stream(mmap, &mut h, &md5_done, cancel);
            let hex = if ok { hex::encode(h.finalize()) } else { String::new() };
            (ok, hex)
        });
        let h_sha = scope.spawn(|| {
            let mut h = sha2::Sha256::new();
            let ok = hash_stream(mmap, &mut h, &sha_done, cancel);
            let hex = if ok { hex::encode(h.finalize()) } else { String::new() };
            (ok, hex)
        });

        // 协调线程：细粒度轮询，保证某一侧算法完工后立即返回（避免小文件
        // 被节流间隔拖慢）；进度本身仍按 PROGRESS_INTERVAL 节流上报。
        let mut last_sent = Instant::now();
        loop {
            // 两侧都结束（正常或异常）即可退出，异常时不死等
            if h_md5.is_finished() && h_sha.is_finished() {
                break;
            }
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            // 取两者已完成字节数的较小值 —— 慢的那个算法决定整体完工进度
            let cur = md5_done
                .load(Ordering::Relaxed)
                .min(sha_done.load(Ordering::Relaxed));
            if last_sent.elapsed() >= PROGRESS_INTERVAL {
                let _ = tx.send(WorkerMsg::Progress {
                    current: cur,
                    total,
                });
                last_sent = Instant::now();
            }
            thread::sleep(POLL_INTERVAL);
        }

        let (m_ok, m_hex) = h_md5.join().unwrap_or((false, String::new()));
        let (s_ok, s_hex) = h_sha.join().unwrap_or((false, String::new()));
        (m_ok, s_ok, m_hex, s_hex)
    });

    if cancel.load(Ordering::Relaxed) {
        return Err(WorkerError::Cancelled);
    }
    if !md5_ok || !sha_ok {
        return Err(WorkerError::Other("计算线程异常终止".into()));
    }

    // 收尾进度，确保进度条走到 100%
    let _ = tx.send(WorkerMsg::Progress {
        current: total,
        total,
    });
    Ok((md5_hex, sha_hex))
}

/// 让一个 hasher 顺序跑完整块数据；`done` 记录已完成字节数供进度读取。
/// 返回 `false` 表示中途收到取消信号。
fn hash_stream<D: Digest>(
    mmap: &[u8],
    hasher: &mut D,
    done: &AtomicU64,
    cancel: &AtomicBool,
) -> bool {
    let mut processed: u64 = 0;
    for chunk in mmap.chunks(CHUNK_SIZE) {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        hasher.update(chunk);
        processed += chunk.len() as u64;
        done.store(processed, Ordering::Relaxed);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 在临时目录创建内容为 `bytes` 的文件，返回路径（由调用方负责删除）。
    /// 文件名带进程 id，避免并发用例互相覆盖。
    fn temp_file(tag: &str, bytes: &[u8]) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("hash_calculator_{}_{tag}", std::process::id()));
        let mut f = std::fs::File::create(&path).expect("create temp file");
        f.write_all(bytes).expect("write temp file");
        f.flush().expect("flush temp file");
        path
    }

    /// 走真实 worker 路径计算，返回 (md5, sha256)；出错则直接 panic。
    fn hash_via_worker(path: &Path, upper: bool) -> (String, String) {
        let (_handle, rx) = spawn(path.to_path_buf(), upper);
        loop {
            match rx.recv().expect("worker channel closed before Done") {
                WorkerMsg::Progress { .. } => {}
                WorkerMsg::Done { md5, sha256, .. } => return (md5, sha256),
                WorkerMsg::Error(e) => panic!("unexpected error: {e}"),
                WorkerMsg::Cancelled => panic!("unexpected cancellation"),
            }
        }
    }

    /// 0 字节文件必须按哈希标准输出空输入摘要，而不是报错「文件为空」。
    #[test]
    fn empty_file_hashes_match_standard() {
        let path = temp_file("empty", b"");
        let (md5, sha256) = hash_via_worker(&path, false);
        let _ = std::fs::remove_file(&path);

        assert_eq!(md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
