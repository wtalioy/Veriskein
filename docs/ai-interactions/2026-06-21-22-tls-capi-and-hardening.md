# 2026-06-21 至 2026-06-22 TLS Prompt 捕获、CAPI 与运行时加固交互记录

## 1. 阶段背景

本阶段目标是从基础 syscall 安全监测推进到多智能体语义监测：将 TLS 明文、PromptObject、SourceArtifact、EvidenceChain 和跨 Agent prompt injection 检测接入同一条可解释证据链。

对应 git 记录主要包括：

- `feat: Improve startup attribution with refactored runtime state`
- `test: Add replay assertions and scenario coverage`
- `feat: Add TLS prompt capture pipeline`
- `feat: Add cross-session prompt injection detection with causal evidence chains`
- `refactor: Replace per-process TLS capture with global OpenSSL attachment`
- `feat: Complete strict TLS attribution and CAPI alerting`
- `feat: Complete runtime degradation, IPC, and cleanup`
- `feat: Complete prompt correlation and daemon operability hardening`
- `feat: Implement runtime capture and live IPC surfaces`

## 2. 使用目标

本阶段使用 AI 编程助手主要处理以下问题：

- 分析 OpenSSL uprobe 捕获明文的实现边界；
- 设计 TLS fragment 到 stream/prompt 的归因与缓存策略；
- 梳理跨 session 文件传播、prompt 匹配、风险 syscall 的因果链；
- 设计 CAPI scoring、MinHash、template suppression、redaction 等机制；
- 为 prompt capture、cross-agent injection、parallel stream 隔离和 redaction 增加测试。

## 3. 代表性交互内容

### 3.1 TLS 捕获路径

围绕 OpenSSL 明文捕获，讨论并采用了以下约束：

- 优先支持动态链接的 `libssl.so.3` 与 `libssl.so.1.1`；
- 使用全局 DSO attachment，而不是按进程反复 attach；
- TLS bytes 到达时，进程归因可能尚未完成，因此需要允许短时等待或降级；
- 不支持静态链接 OpenSSL、BoringSSL、Go-native TLS、rustls 时，需要通过 fallback/visibility 表达，而不是输出过强结论。

采用结果：`tls_uprobe.bpf.c`、`veriskein-bpf`、`veriskein-state-net`、`veriskein-content` 形成 TLS fragment 到 PromptObject 的链路。

### 3.2 Prompt 与 EvidenceChain

围绕“上游文件摘录 → 下游 prompt → 高危 syscall”的链路，采用了以下策略：

- prompt 与 artifact 都保留稳定 ID、normalized hash、MinHash signature；
- 跨 session 匹配必须先有显式传播事实，再考虑文本相似度；
- CAPI chain 必须满足 artifact -> prompt -> risky event 的时间顺序；
- alert 中必须包含 `chain_id`、`prompt_ref`、`excerpt_match`、`syscall` 等可解释证据；
- 输出前对 API key、PEM、长 token、家目录等敏感片段做 redaction。

采用结果：实现了 `cross_agent_prompt_injection` 检测和 CAPI scoring，并通过 replay 与 live TLS 场景验证。

### 3.3 并发流隔离与降级诚实

针对 TLS 并发 stream 与运行时可见性不足，讨论并采用：

- prompt 聚合按 stream scoped boundary，不能跨 stream 合并；
- `VisibilityState` 映射到 alert fallback，由 alert policy 统一处理；
- ringbuf 压力、TLS 不可见、prompt evidence 不完整时，不能输出过强 severity/confidence；
- degradation scenario 要验证降级时仍有基础告警，但 CAPI 不应过度宣称。

采用结果：增加了 parallel stream replay/live 场景、degradation honesty 场景和 alert policy 测试。

## 4. 人工审阅与验证

本阶段采用的 AI 建议通过以下方式确认：

```bash
cargo test --workspace
target/debug/veriskein-test replay --fixture tests/replay/cross_agent_prompt_injection.jsonl --output <alerts> --workspace "$PWD"
target/debug/veriskein-test assert --expect tests/replay/cross_agent_prompt_injection.expect.jsonl --actual <alerts>
sudo -E ./tests/run_all.sh --only tls_openssl_prompt_capture
sudo -E ./tests/run_all.sh --only cross_agent_prompt_injection_tls
sudo -E ./tests/run_all.sh --only cross_agent_prompt_injection_parallel_streams_tls
sudo -E ./tests/run_all.sh --only degradation_honesty
```

## 5. 本阶段产出

- TLS Prompt 捕获链路；
- PromptObject / SourceArtifact / EvidenceChain；
- CAPI detector；
- CAPI scoring 与 redaction；
- replay fixture 与 live TLS 场景；
- IPC live alert / metrics / event / graph 基础能力；
- 运行时降级与 alert policy 加固。

