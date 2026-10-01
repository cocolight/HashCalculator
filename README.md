# HashCalculator

A lightweight, cross-platform MD5/SHA-256 hash calculator built with **Rust + egui**.

Supports memory-mapped file reading, async computation with progress bar, hash verification, one-click clipboard copy, and batch hashing of many files.

轻量级哈希值计算工具，基于 Rust + egui 构建，支持 MD5/SHA-256，内存映射读取、异步进度、哈希校验、一键复制与多文件批量计算。

## Features

- **Algorithms**: MD5 + SHA-256 computed in parallel in a background thread.
- **Memory-mapped I/O**: large files are streamed via `memmap2`, avoiding full-file load.
- **Async progress**: live progress bar with current/total size, no UI freeze.
- **Cancellation**: stop a running computation at any time.
- **Batch mode**: pick many files or a folder (direct files only) and hash them in sequence, with a virtualized result table, CSV/TXT export and copy-to-clipboard.
- **Hash verification**: paste an expected MD5/SHA-256 and get ✓/✗ instantly.
- **Read-only result**: result panel cannot be edited accidentally.
- **Cross-platform**: pure Rust, builds for Windows / Linux / macOS.

## Usage

Single file tab:

1. Click **浏览...** to pick a file.
2. Toggle **大写字母** if you want uppercase hex (default on).
3. Click **计算哈希**; the progress bar and status line update in real time.
4. Click **复制结果** to copy filename / size / mtime / MD5 / SHA-256.
5. In **哈希验证**, paste expected values and click **验证** to compare.

Batch tab:

1. Click **添加文件** (multi-select) or **添加文件夹** (direct files only, no recursion).
2. Click **开始计算** to hash the list in sequence; each file still uses two threads internally.
3. Tick rows to narrow the export scope — with no tick, export/copy covers every row.
4. Use **导出 CSV** (UTF-8 BOM, so Excel shows CJK paths correctly), **导出 TXT**, or **复制选中**.

## Build

```bash
# debug
cargo run

# release (smaller binary)
cargo build --release

# unit tests
cargo test
```

Requires a recent stable Rust toolchain (tested with 1.98). On Windows, the MSVC toolchain is used by default.

## Project Layout

```
src/
  main.rs      # entry, creates the eframe window; also the headless --bench entry
  app.rs       # HashApp: single-file and batch tabs (egui immediate-mode UI + state)
  worker.rs    # background thread: memmap + parallel MD5/SHA-256, hash_file()
  batch.rs     # sequential batch runner over hash_file, plus CSV/TXT/TSV export
  format.rs    # helpers: file size / time formatting
docs/
  perf-plan.md # large-file performance notes
  roadmap.md   # development roadmap and priorities
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
