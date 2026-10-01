下面是完整方案（**当前是 Ask 只读模式，我把方案原文输出在对话里，不落盘** —— 需要存成文件的话切 Agent 模式我来写）。

---

# HashCalculator 大文件性能优化方案

**项目**：`e:\Project\HashCalculator` v0.4.1（Rust + egui）
**目标**：GB 级文件计算耗时降到当前的 1/3 ~ 1/5，且哈希结果与系统工具逐位一致

## 验收标准（每个阶段都要过）

| 项     | 标准                                                         |
| ------ | ------------------------------------------------------------ |
| 正确性 | MD5/SHA-256 与 `certutil -hashfile <文件> SHA256` / `MD5` 完全一致 |
| 小文件 | <100MB 文件耗时**不得劣化**（这档最容易在重构中被顺手搞坏）  |
| 中文件 | 1GB，记录吞吐 MB/s，与前序阶段对比必须变快                   |
| 大文件 | 4GB+ 不出现卡顿、取消可用、内存占用不随文件增大              |

---

## 阶段 0 · 前置（必须先做，零代码）

1. `git tag v0.4.1-baseline`，之后**每个阶段末尾打一个 tag**（`v0.4.2-asm`、`v0.4.3-ui`、`v0.4.4-io`、`v0.4.5-parallel`），保证任意阶段可单独回退。
2. 造 4 个基准文件：`20MB` / `1GB` / `4GB` / `4GB稀疏`，放到固定目录。
3. 填基线表（跑 release 版）：

| 文件 | 当前耗时 | 吞吐 | 只算 MD5 | 只算 SHA256 |
| ---- | -------- | ---- | -------- | ----------- |
| 20MB |          |      |          |             |
| 1GB  |          |      |          |             |
| 4GB  |          |      |          |             |

> 没这张表，阶段 3/4 做完你只能靠感觉判断好坏。

---

## 阶段 1 · 配置层（零风险，可能直接解决问题）

**改动**

`Cargo.toml:18-19`
```toml
md-5  = { version = "0.11", features = ["asm"] }
sha2  = { version = "0.11", features = ["asm"] }
```

同时确认你跑的是 `cargo build --release`（`Cargo.toml:23-27` 已配 `opt-level=3 / lto=thin`，配置没问题）。

**验证**
- 重新 build，重跑阶段 0 的基准表
- 预期 SHA-256 快 3~6 倍（x86-64 2013 年后 CPU 的 SHA-NI 指令），MD5 快 2~3 倍

**风险与回退**
- `asm` 在 Windows 上会触发额外 `cc` 构建步骤；若交叉编译受限，把 feature 去掉即可还原，`Cargo.toml` 一行回滚
- 极老 CPU 无 SHA-NI 时该实现内部通常有 `cpufeatures` 运行时探测（以 rustdoc 为准），不会直接崩
- **回退**：`git checkout v0.4.1-baseline -- Cargo.toml Cargo.lock`

> 💡 如果这一步之后已经达标 70%，**方案可以到此为止**。

---

## 阶段 2 · UI 观感与线程安全（正交、低风险）

**改动**

1. `worker.rs:100` 进度阈值 256MB → 改为**按耗时节流**：
```rust
const PROGRESS_INTERVAL_MS: u128 = 100; // 最多 10 次/秒
```
`worker.rs:102-124` 里 `last_update` 从记录字节数改为记录 `Instant`，每 ≥100ms 发一次 `Progress`。
2. 删掉 `worker.rs:110` 和 `worker.rs:122` 的 `ctx.request_repaint()` —— egui 不是严格线程安全的，UI 线程 `app.rs:334-336` 已经每帧重绘了。
3. 顺手把 `worker.rs:113` 的取消粒度跟着新块大小调小（原 64MB 一块，取消要等 64MB）。

**验证**：进度条连续平滑；点「取消」后 1~2GB 文件应在 1 秒内响应（原来可能要 2~3 秒）。哈希结果不变化（纯 UI）。

**回退**：一行 `git checkout` 即可，无联动。

---

## 阶段 3 · I/O 层改造（**本轮唯一中风险**，核心是双轨）

**动机**：`worker.rs:94` 一次性 `Mmap::map` 整个文件，超大文件时长期占用地址空间与页缓存，且在 SMB/HDD/冷盘上缺页异常可能拖慢。

**改动（双轨并存，不要一次删旧的）**

把现有 `compute` 拆成两个实现，用一个模块级常量切换：

- `compute_mmap()` —— 原逻辑原样保留
- `compute_stream()` —— 新逻辑，顺序读，4MB 缓冲：

```rust
const BUF_SIZE: usize = 4 * 1024 * 1024;
const IO_MODE_MMAP: bool = true; // 阶段 3 验证期保持 true，跑通后改 false

let mut reader = std::io::BufReader::with_capacity(BUF_SIZE, file);
let mut buf = vec![0u8; BUF_SIZE];
let mut current = 0u64;
loop {
    let n = reader.read(&mut buf)?;              // Read::read 可能短读，循环保底
    if n == 0 { break; }
    md5.update(&buf[..n]);
    sha256.update(&buf[..n]);
    current += n as u64;
    // ... 进度 + cancel 检查 ...
}
```

**验证（这一步的关键纪律）**
1. `IO_MODE_MMAP = true` 跑一遍 → 记下 4 个基准文件的哈希与耗时
2. `IO_MODE_MMAP = false` 跑一遍 → **四条哈希必须与上一步逐位一致**（这是双轨验收的核心）
3. 再与 `certutil` 交叉验证一次
4. 三条都过 → `IO_MODE_MMAP` 保留为 `false`，**下一阶段之前**再删 `compute_mmap()`
5. 重跑阶段 0 基准表，看吞吐是否提升

**回退**：`git checkout v0.4.3-ui`（阶段 2 的 tag），IO 相关改动全部作废，零传染。

**风险点**：`Read::read` 允许短读，必须循环读到 `n == 0` 或累计够一块才退出；漏了会在某些文件系统上丢数据。

---

## 阶段 4 · 并行化（收益最大、风险最高，放最后）

拆成两小步，**不要一次做完**：

### 4a · MD5 与 SHA-256 分占两核（先拿 1.7 倍）

`worker.rs:55` 的 `mpsc::Sender` 是 `Clone`，可以廉价复制：

```
主线程：顺序读 → 每块 tx_md5.send(chunk.clone()); tx_sha.send(chunk.clone());
线程A：只 update md5， finalize 后经内部 channel 回传
线程B：只 update sha256，同回传
主线程：join 后合并结果
```

- 改动只在 `spawn` / `compute` 两个函数，**不动 UI**
- 预期：总耗时 ≈ max(md5, sha256)，接近减半
- 若读线程扇出大块（4MB）的两次 memcpy 是瓶颈，再降到 1MB 块或改成 `Arc<Vec<u8>>` 试

### 4b · 分块多线程（只在 4a 数据不够好时做）

按 **512 字节对齐**切块（压缩块边界），N = `min(num_cpus, 4)` 个线程各自推进 midstate，主线程负责从块的起始状态续算、以及最后一块的 padding。

> ⚠️ 需要 `digest` crate 的 midstate 续算接口（`Digest::midstate()` 及从 midstate 恢复的构造器，不同版本命名如 `new_with_prefix` / `from_midstate` / `from_core`，**开工时以 rustdoc 核对签名再写**）。

**这一步的三个坑**（提前知道能省很多时间）：
1. **分块点必须 512 字节对齐**，最后一块的 padding 只能在主线程补 —— 这里写错会让文件尾部哈希错误，而且只有大文件才暴露
2. **取消要广播**：`cancel` 现在是一个 `AtomicBool`（`worker.rs:29`），并行后需要 `Arc<AtomicBool>` + 所有线程 `join` 后再返回
3. **留并发度开关**：做成 `num_threads` 参数，出问题一行设成 `1` 就能降级，不必重新编译定位

**验证**：4a/4b 每一小步结束都重跑 4 个基准文件的哈希一致性 + 耗时表，任何一条哈希不一致立刻停手回退到 `v0.4.4-io`。

---

## 阶段 5 · 收尾（**单独一个 commit，不要和前面的改动混在一起**）

- 删除 `compute_mmap()` 与所有切换开关
- 恢复/清理进度与重绘逻辑
- 最终全量回归：4 个文件 × `certutil` 交叉验证 + 基准表出最终报告
- `git tag v0.4.6-opt`，顺手发版

---

## 一张图看顺序与依赖关系

```
阶段0 测量基线  →  阶段1 asm配置(零风险)
                    ↓
              阶段2 UI/取消(正交)
                    ↓
              阶段3 I/O双轨(中风险)  ← 必须先双轨验证一致，再删旧
                    ↓
              阶段4a 2线程并行 → 阶段4b N线程并行(高风险)
                    ↓
              阶段5 删旧代码 + 发版
  每阶段一个 tag，任意阶段 git checkout 可精确回退
```

## 防"大面积毁坏"的三条硬纪律

1. **改动面从小到大**：`Cargo.toml`（1行）→ UI（几十行）→ I/O（一个函数）→ 并发（两个函数）
2. **并行永远最后**：并发 bug 不可复现，前面全部是已验证的确定性代码，出问题能二分定位
3. **删旧代码永远单独一个 commit**：和"改新逻辑"放一起，一旦出问题你分不清是改坏了还是删坏了

---

要不要我把它落成一份可直接照着执行的 **Markdown 实施文档**（含每步的命令、代码 diff、验证命令、回退命令）？切 **Agent 模式**我就写进项目里（比如 `docs/perf-plan.md`）；也可以直接在对话里继续讨论哪一步我想再细化。