# 2026-06-30 提交前验证、性能基准与材料检查交互记录

## 1. 阶段背景

本阶段围绕初赛提交前检查展开，目标是确认功能实现、测试覆盖、性能结果、git 过程记录和比赛材料是否能够支撑完整提交。

对应 git 记录主要包括：

- `refactor: Make bounded retention refresh order efficient`
- `feat: Stabilize IPC history queries and queue behavior`
- `feat: Harden fd content capture and MCP anomaly parsing`
- `feat: Project prompt capture modes in alerts`
- `fix: Let perf measurement use time output without JSON`
- `feat: Add toggleable TLS and content capture modes to isolate capture overhead`
- `test: Add live capture-overhead benchmark with representative same-workload methodology`

## 2. 使用目标

本阶段使用 AI 编程助手主要处理以下问题：

- 对照本地实现计划和任务要求判断 Phase 0-6 完成度；
- 核查测试文件是否覆盖主线功能；
- 运行 workspace 单测、replay、live BPF scenario；
- 检查新增性能基准的方法论和脚本可执行性；
- 分析 git 历史是否满足过程记录要求；
- 梳理设计文档、PPT、演示视频和合规材料缺口；
- 整理 AI 使用声明与交互记录归档。

## 3. 代表性交互内容

### 3.1 完成度与测试覆盖检查

交互中按本地仓库结构检查了：

- `crates/*`
- `bpf/*`
- `config/*`
- `tests/replay/*`
- `tests/scenarios/*`
- `tests/perf/*`
- `README.md`
- 赛题题目要求（本地参考，不随作品提交）

形成的判断：

- Phase 0-5 主线功能已有完整代码和测试证据；
- Phase 6 已包含 `content_io`、MCP parsing、MCP Tool Spoofing hooks，但缺少独立 live MCP spoofing 场景和真实 stdio/pipe 内容捕获场景；
- 项目当前没有可视化前端，交付形态是 daemon + CLI + NDJSON + IPC。

### 3.2 构建、单测与 live 场景

提交前执行并记录了以下验证：

```bash
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace -- -D warnings
```

环境问题与处理：

- 构建 BPF 相关 crate 时需要 `pkg-config`、`libelf-dev`、`libzstd-dev`；
- live scenario 需要 sudo/root 权限和 BTF；
- `sensitive_file_access_shadow` 依赖 `zsh`，安装后全量 live suite 通过。

live scenario 通过项：

- `benign_shell`
- `unexpected_shell_basic`
- `sensitive_file_access_shadow`
- `out_of_workspace_deletion`
- `deadloop_waste`
- `tls_openssl_prompt_capture`
- `cross_agent_prompt_injection_tls`
- `cross_agent_prompt_injection_parallel_streams_tls`
- `degradation_honesty`

replay 通过项：

- `alert_redaction`
- `attribution_shell`
- `benign_shell`
- `cross_agent_prompt_injection`
- `cross_agent_prompt_injection_parallel_streams`
- `deadloop_waste`
- `out_of_workspace_deletion`
- `sensitive_file_access_shadow`
- `startup_shell`
- `tls_prompt_same_session`

### 3.3 性能基准检查

本阶段检查了 `tests/perf/` 的真实负载基准：

- `tests/perf/run.sh`
- `tests/perf/README.md`
- `tests/perf/workloads/mixed_workload.sh`

确认的优点：

- 使用同一个 workload 比较不同 capture mode，比旧 smoke 更公平；
- daemon 启动在计时区外，避免把 attach/startup 成本算入 workload；
- `--disable-tls` 可以用于隔离 OpenSSL uprobe 成本；
- report 可以输出 `report.json` 与 `report.md`。

同时保留的注意事项：

- `kernel-only` 当前仍会 attach `content_io` 程序，只是白名单为空；
- `full --enable-content-capture` 在当前 workload 下不一定触发真实 stdio/MCP 内容捕获；
- perf report 中 `events_total` 与 `drops_total` 仍为脚本输入中的 0，不能作为真实事件计数证据。

## 5. 本阶段产出

- 完成度和测试覆盖判断；
- live scenario 与 replay 验证记录；
- 性能基准审查意见；
- 提交材料缺口清单；
- AI 使用披露和交互记录整理。
