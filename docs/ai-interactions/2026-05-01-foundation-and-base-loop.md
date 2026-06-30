# 2026-05-01 基础框架与基础异常检测交互记录

## 1. 阶段背景

本阶段围绕 Veriskein 的最小可运行数据面展开，目标是先建立可编译、可测试、可回放的工程骨架，再完成基础 eBPF 事件采集、归一化、会话归因和基础告警闭环。

对应 git 记录主要包括：

- `Initial commit`
- `feat: Add preflight checks and new crates`
- `feat: Implement phase 1 runtime pipeline`
- `feat: Add phase 1 scenario harness`
- `refactor: Split detector, graph, alert, bpf, and collector crate roots into focused modules while moving unit tests into sibling test files`
- `fix: Preserve syscall results and procfs-backed fd state during normalization so downstream detection keeps accurate path context`
- `refactor: Harden live event capture and process state tracking for more accurate attribution`
- `feat: Add daemon-backed scenario runs with per-run config roots for live verification`
- `fix: Detect denied sensitive file access so live fixtures still surface risky reads`

## 2. 使用目标

本阶段使用 AI 编程助手主要处理以下问题：

- 将赛题需求拆分为可实现的 Rust workspace 与 eBPF 模块边界；
- 设计事件 ABI、collector、normalizer、graph、detector、alert sink 的分层关系；
- 梳理 `lib.rs` 保持轻量、测试放入 `src/tests.rs` 的模块组织方式；
- 为基础场景建立 replay 与 live scenario 验证脚本；
- 定位路径归一化、fd 状态继承、敏感路径访问等边界问题。

## 3. 代表性交互内容

### 3.1 工程骨架与模块边界

围绕“crate root 不承担过多职责”的要求，讨论并采用了以下拆分方式：

- `veriskein-proto`：事件 ABI、ID、默认阈值和解析；
- `veriskein-collector`：ringbuf 数据接收、seq 检查和 drop 合成；
- `veriskein-normalizer`：进程、cwd、fd、路径与 workspace/sensitive 判定；
- `veriskein-graph`：session、agent、role 归因；
- `veriskein-detectors`：基础异常检测；
- `veriskein-alert`：告警 schema、投影和 NDJSON 输出；
- `veriskein-daemon`：CLI、preflight、运行时接线和场景驱动。

采用结果：workspace 可以按 crate 独立测试，`lib.rs` 主要作为 re-export surface，模块边界保持清晰。

### 3.2 基础事件与归一化

围绕 `exec/fork/exit/chdir/fd/open/unlink/rename/connect` 事件，讨论过以下实现点：

- BPF 侧保留 syscall 返回值，避免失败操作被误判为成功风险；
- fd 表需要在 fork 时 copy-on-write，exec 后保留未关闭 fd；
- `AT_FDCWD`、stale dirfd、路径穿越、敏感路径匹配需要独立测试；
- denied sensitive access 也应保留风险信号，因为攻击意图仍然存在。

采用结果：normalizer 增加了 fd/cwd/path 状态维护，基础 detector 能从 `NormalizedEvent` 获取稳定路径和访问上下文。

### 3.3 基础场景测试

为 Phase 1 基础闭环整理了以下场景：

- `unexpected_shell_basic`
- `sensitive_file_access_shadow`
- `out_of_workspace_deletion`
- `benign_shell`

交互中重点关注：

- 场景运行目录隔离；
- 每个场景独立复制 config；
- alert 输出用 `veriskein-test assert` 校验；
- 负例必须明确断言“不出现不该出现的告警”。

采用结果：`tests/run_all.sh` 可以按场景启动 daemon、执行 workload、收集 alerts 并断言结果。

## 4. 人工审阅与验证

本阶段采用的 AI 建议均通过以下方式确认：

```bash
cargo test -p veriskein-proto
cargo test -p veriskein-alert
cargo test -p veriskein-normalizer
cargo test -p veriskein-graph
cargo test -p veriskein-detectors
sudo -E ./tests/run_all.sh --only unexpected_shell_basic
sudo -E ./tests/run_all.sh --only sensitive_file_access_shadow
sudo -E ./tests/run_all.sh --only out_of_workspace_deletion
```

最终进入仓库的内容以 git commit 为准，未直接使用未经审阅的生成代码。

## 5. 本阶段产出

- 多 crate Rust workspace；
- eBPF 采集程序与用户态事件解析；
- 基础状态归一化和 session seed 归因；
- 三类基础 detector；
- schema-valid alert 输出；
- 基础 replay/live scenario 测试。
