# AI 工具使用声明（AI Tool Usage Disclosure）

## 1. 合规声明

- 本参赛队在开发过程中合理使用了与大模型相关的 AI 辅助工具。
- 本队对所有由 AI 辅助生成的内容均进行了人工审阅、修改与验证，最终交付物的设计决策、
  架构、核心算法与正确性由参赛队员负责并把控。
- 凡采纳 AI 辅助产出的代码、测试或文档，均经过人工审阅后进入仓库；
  git 提交记录反映了功能迭代过程，AI 使用情况由本文档、交互记录附件、设计方案文档和答辩 PPT 单独说明。

## 2. 使用的 AI 工具与大模型清单

| 工具 / 平台 | 类型 | 关联大模型 | 主要用途 |
| --- | --- | --- | --- |
| Cursor IDE（内置 AI Agent） | AI 编程助手 / 智能体 | Auto、Composer2.5、GPT-5.5、Opus4.8、Sonnet4.6 （按实际会话选择）| 代码生成与重构、调试、文档撰写、命令执行与测试验证 |
| 大语言模型 - OpenAI| 大语言模型 | GPT-5.5 | 架构讨论、代码实现、文档草拟、测试分析 |

## 3. AI 工具的使用场景（按开发活动划分）

下列场景均为本项目实际发生的 AI 使用情形：

1. **代码实现与重构**
   - 辅助生成 Rust 多 crate 工程骨架与模块拆分（如将各 crate 的 `lib.rs`
     拆分为聚焦的内部模块，单测移入 `src/tests.rs`）。
   - 辅助实现可切换的捕获模式开关（`BpfRuntimeConfig.tls_enabled`、daemon 的
     `--disable-tls` / `--enable-content-capture` 参数及 `driver.rs` 接线）。

2. **eBPF / 系统编程咨询**
   - 查询 eBPF（kprobes/tracepoints/uprobes）、libbpf、OpenSSL 明文 Hook 等用法与边界条件。
   - 讨论非侵入式截获 HTTPS 明文的实现约束（如 OpenSSL 动态链接、x86_64 平台限制）。

3. **测试与验证**
   - 辅助设计和编写单元测试、replay 回放断言、live 场景测试、性能基准脚本（`tests/perf/`）。
   - 辅助执行和分析 `cargo test --workspace`、`cargo fmt --all --check`、`cargo clippy --workspace -- -D warnings`、
     `tests/run_all.sh`、`veriskein-test replay/assert` 等验证结果。
   - 在缺少系统依赖（`pkg-config`、`libelf`、`libzstd`、`zsh` 等）的环境中，辅助定位构建或场景失败原因。

4. **性能基准方法学**
   - 辅助设计"同一负载、仅切换挂载 BPF 程序"的公平对比基准，区分"纯捕获开销 vs 端到端"，
     并辅助分析旧 smoke 中 30% 实为场景差异而非捕获开销的问题。

5. **文档与材料撰写**
   - 辅助整理`README.md`、设计方案文档、答辩 PPT 大纲等

6. **项目分析与决策支持**
   - 辅助评估项目完成度、对照赛题评审要点、梳理待补交付物清单。

## 4. AI 工具的成果（哪些内容由 AI 辅助产出）

本队对成果归类如下：

- **由 AI 辅助生成、经人工审阅修改后采用**：
  - 部分 Rust 实现代码与模块骨架、单元测试用例。
  - replay / live scenario 测试用例与断言、性能基准脚本（`tests/perf/run.sh`、`workloads/mixed_workload.sh`）的初稿。
  - 测试覆盖分析、失败原因定位和性能报告解释的过程性记录。
  - 多数文档初稿（设计文档、README、本披露文档）。
- **由参赛队主导设计、AI 仅作实现/表达辅助**：
  - 系统总体架构（eBPF 采集 → 归一化 → 会话图 → 内容/TLS → 关联 → 检测 → 告警/IPC）。
  - 跨层因果关联策略（突破"语义鸿沟"：上游工件 → 下游 prompt → 高危 syscall 的证据链）。
  - 五类异常检测逻辑、告警 schema、降级诚实（degradation honesty）策略。
  - 威胁模型定义与各检测场景的判定规则。
- **完全由参赛队人工完成的把控**：
  - 最终架构与算法决策、正确性验证、性能指标确认、对赛题要求的取舍。

## 5. 与 AI 工具的交互记录

- 交互记录留存于本仓库：
  - `docs/ai-interactions/README.md`：交互记录归档索引与归档原则。
  - `docs/ai-interactions/2026-05-01-foundation-and-base-loop.md`：基础工程骨架、BPF 事件、
    归一化、基础 detector 与场景测试相关记录。
  - `docs/ai-interactions/2026-06-21-22-tls-capi-and-hardening.md`：TLS Prompt 捕获、CAPI、
    降级诚实和 IPC 加固相关记录。
  - `docs/ai-interactions/2026-06-30-submission-verification-and-perf.md`：提交前测试验证、
    性能基准检查、Phase 6 进度、材料缺口和 AI 披露整理相关记录。
- git 提交记录体现了项目功能迭代过程；AI 使用情况以本文档和 `docs/ai-interactions/` 为准。
