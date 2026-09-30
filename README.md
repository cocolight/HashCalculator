# HashCalculator

A lightweight, cross-platform MD5/SHA-256 hash calculator built with **Rust + egui**.

Supports memory-mapped file reading, async computation with progress bar, hash verification, and one-click clipboard copy.

轻量级哈希值计算工具，基于 Rust + egui 构建，支持 MD5/SHA-256，内存映射读取、异步进度、哈希校验与一键复制。

## Features

- **Algorithms**: MD5 + SHA-256 computed in parallel in a background thread.
- **Memory-mapped I/O**: large files are streamed via `memmap2`, avoiding full-file load.
- **Async progress**: live progress bar with current/total size, no UI freeze.
- **Cancellation**: stop a running computation at any time.
- **Hash verification**: paste an expected MD5/SHA-256 and get ✓/✗ instantly.
- **Read-only result**: result panel cannot be edited accidentally.
- **Cross-platform**: pure Rust, builds for Windows / Linux / macOS.

## Usage

1. Click **浏览...** to pick a file.
2. Toggle **大写字母** if you want uppercase hex (default on).
3. Click **计算哈希**; the progress bar and status line update in real time.
4. Click **复制结果** to copy filename / size / mtime / MD5 / SHA-256.
5. In **哈希验证**, paste expected values and click **验证** to compare.

## Build

```bash
# debug
cargo run

# release (smaller binary)
cargo build --release
```

Requires a recent stable Rust toolchain (tested with 1.98). On Windows, the MSVC toolchain is used by default.

## Project Layout

```
src/
  main.rs      # entry, creates the eframe window
  app.rs       # HashApp: egui immediate-mode UI + state
  worker.rs    # background thread: memmap + MD5/SHA-256, channel progress
  format.rs    # helpers: file size / time formatting
Cargo.toml
```

## Dependencies

| crate     | purpose                          |
| --------- | -------------------------------- |
| eframe    | egui native window host          |
| egui      | immediate-mode GUI              |
| rfd       | native file dialog              |
| memmap2   | cross-platform memory-mapped IO |
| md-5      | MD5 (RustCrypto)                 |
| sha2      | SHA-256 (RustCrypto)             |
| arboard   | clipboard copy                   |
| chrono    | modification-time formatting     |

## License

GPL-3.0-only. See [LICENSE](LICENSE).

Copyright (c) cocolight.
