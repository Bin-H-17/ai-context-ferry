# ai-context-ferry
[![CI](https://github.com/Bin-H-17/ai-context-ferry/actions/workflows/ci.yml/badge.svg)](https://github.com/Bin-H-17/ai-context-ferry/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Bin-H-17/ai-context-ferry/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Bin-H-17/ai-context-ferry)
[![SonarCloud](https://sonarcloud.io/api/project_badges/measure?project=Bin-H-17_ai-context-ferry&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=Bin-H-17_ai-context-ferry)
[![codecov](https://codecov.io/gh/Bin-H-17/ai-context-ferry/branch/main/graph/badge.svg)](https://codecov.io/gh/Bin-H-17/ai-context-ferry)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> 开源、跨平台的 AI 助手上下文迁移与交接工具。
> 多平台适配器 ＋ 标准化加密资产包 ＋ 自动交接文档。
> 人 ↔ 人、Agent ↔ Agent 的场景都能适应。
>
> **EN**: An open-source, cross-platform tool for migrating and handing off AI assistant context.
> Multi-platform adapters + standardized encrypted asset bundle + auto handoff doc.
> Works for human-to-human and agent-to-agent scenarios.

[中文](#中文) | [English](#english)

---

## 中文

### 问题
面向一般与非正式的协作和上下文轻快交接转换场景。额度耗尽、换账号、换设备、团队协作交接时，对话历史 / 长期记忆 / 用户画像 / Skills / 配置 / 自动化任务散落在各个 AI 助手账号里。手动搬运既丢上下文又耗时，且无据可查、容易泄露凭证。

### 方案：三步 + 加密
从一个统一 CLI 出发：
1. **导出（`export`）**：通过各平台适配器拉取对话、记忆、配置等资产，并**自动脱敏**密钥/令牌。
2. **打包（`package`）**：按标准化资产清单（`asset-manifest` v2.0.0，见 `spec/`）生成**加密资产包**（`.ferry`）。
3. **交接（`handoff`）**：解密后自动渲染结构化交接文档（`SESSION.md`，见 `templates/`），含资产清单、关键决策、遗留阻塞、下一步建议。

### 加密模型
- **口令模式（默认）**：`AES-256-GCM` 加密，`Argon2id`（抗 GPU/ASIC）派生密钥。零密钥基础设施，适合个人多账号/多设备迁移。
- **收件人模式（可选）**：`X25519 ECDH + HKDF` 协商密钥（借鉴 [age](https://github.com/FiloSottile/age) 的设计哲学）。用对方公钥加密，对方用自己私钥解密，无需共享口令——适合把资产包交给另一个账号/人。
- 信封为**自描述 JSON**，便于调试与跨语言解析；所有原语来自 `cryptography` 库。

### 特性
- 多平台导出适配器：**OpenAI Codex** / **Claude Code** / **WorkBuddy**（均已实现并测试）；**Hermes**
- 标准化 `asset-manifest` 数据模型（`spec/asset-manifest.schema.json`，v2.0.0）
- 导出即脱敏：正则识别并遮盖密钥/令牌/JWT/私钥，被遮类别登记进 `handoff.withheld_context_summary`
- 自动生成 `SESSION.md` 交接文档（Jinja2 模板）
- `export → package → handoff` 全流程均有测试覆盖
- 纯本地、开源（MIT）、可审计

### 安装
```bash
pip install -e .
# 或直接用 venv
python -m venv .venv && .venv/Scripts/python -m pip install cryptography jinja2 jsonschema
```

### 用法
```bash
# 列出已注册平台
ai-context-ferry list-platforms

# 1) 导出（account 留空=当前用户主目录；也可指定备份/挂载目录）
ai-context-ferry export --platform claude_code --account "" --out ./exported

# 2a) 口令模式打包（交互输入口令）
ai-context-ferry package --input ./exported --output ./bundle.ferry --passphrase "你的口令"

# 2b) 收件人模式打包（先 keygen 生成对方公钥）
ai-context-ferry keygen --save ./keys.json
ai-context-ferry package --input ./exported --output ./bundle.ferry \
    --recipient "<对方 X25519 公钥 base64>"

# 3) 交接：解密并渲染 SESSION.md
ai-context-ferry handoff --bundle ./bundle.ferry --output ./SESSION.md --passphrase "你的口令"
# 收件人模式：--identity "<接收方私钥 base64>"

# 校验清单是否符合 schema
ai-context-ferry validate --manifest ./exported/asset-manifest.json
```

### 平台磁盘布局（依据公开文档 + 已知结构构建）
- **Claude Code**：`~/.claude/{CLAUDE.md, settings.json, skills/, commands/, agents/, projects/<encoded-path>/<uuid>.jsonl, history.jsonl}` 及 `~/.claude.json`（projects + MCP）。
- **Codex**：`~/.codex/{AGENTS.md, config.toml, rules/, history.jsonl, sessions/**/rollout-*.jsonl, auth.json（令牌，必脱敏）, state_5.sqlite}`。
- **WorkBuddy**：`~/.workbuddy/{MEMORY.md, USER.md, SOUL.md, IDENTITY.md（画像记忆）, memory/*.md（项目记忆）, skills/（可复用资产）, settings.json（可能含令牌）, workbuddy.db（自动化 automations，导出为脱敏 JSON 快照）, projects/（仅索引）}`。本适配器为项目自研，无外部开源可抄。

---

## English

**ai-context-ferry** is an open-source, cross-platform CLI to migrate and hand off your AI assistant context (conversations, long-term memory, user profiles, skills, configs, automations) — encrypted and standardized.
Multi-platform adapters + standardized encrypted asset bundle + auto handoff doc.

### The problem
Built for casual and informal collaboration, and lightweight context handoffs. When quota runs out, you switch accounts or devices, or hand off within a team, conversations / long-term memory / user profiles / Skills / configs / automations are scattered across AI assistant accounts. Manual migration loses context, wastes time, leaves no audit trail, and risks leaking credentials.

### Solution: three steps + encryption
One unified CLI:
1. **`export`** — pull conversations, memory, configs and other assets via per-platform adapters, with **automatic redaction** of keys/tokens.
2. **`package`** — bundle into an **encrypted asset package** (`.ferry`) following the standardized asset manifest (`asset-manifest` v2.0.0, see `spec/`).
3. **`handoff`** — decrypt and render a structured handoff doc (`SESSION.md`, see `templates/`) with asset inventory, key decisions, remaining blockers, and next-step suggestions.

### Encryption model
- **Passphrase mode (default)**: `AES-256-GCM` encryption, `Argon2id` (GPU/ASIC-resistant) key derivation. Zero key infrastructure — suitable for personal migration across accounts/devices.
- **Recipient mode (optional)**: `X25519 ECDH + HKDF` key agreement (borrowing [age](https://github.com/FiloSottile/age)'s design philosophy). Encrypt with the recipient's public key; they decrypt with their own private key — no shared passphrase needed. Suitable for handing the bundle to another account/person.
- The envelope is **self-describing JSON**, easy to debug and parse cross-language; all primitives come from the `cryptography` library.

### Features
- Multi-platform export adapters: **OpenAI Codex** / **Claude Code** / **WorkBuddy** (implemented and tested); **Hermes**
- Standardized `asset-manifest` data model (`spec/asset-manifest.schema.json`, v2.0.0)
- Redact-on-export: regex-based detection and masking of keys/tokens/JWTs/private keys; masked categories recorded in `handoff.withheld_context_summary`
- Auto-generated `SESSION.md` handoff doc (Jinja2 template)
- `export → package → handoff` full flow covered by tests
- Fully local, open source (MIT), auditable

### Install
```bash
pip install -e .
# or use a venv directly
python -m venv .venv && .venv/Scripts/python -m pip install cryptography jinja2 jsonschema
```

### Usage
```bash
# List registered platforms
ai-context-ferry list-platforms

# 1) Export (empty account = current user home dir; can also point at a backup/mounted dir)
ai-context-ferry export --platform claude_code --account "" --out ./exported

# 2a) Package in passphrase mode (interactive passphrase)
ai-context-ferry package --input ./exported --output ./bundle.ferry --passphrase "your passphrase"

# 2b) Package in recipient mode (keygen first to get the recipient's public key)
ai-context-ferry keygen --save ./keys.json
ai-context-ferry package --input ./exported --output ./bundle.ferry \
    --recipient "<recipient X25519 public key base64>"

# 3) Hand off: decrypt and render SESSION.md
ai-context-ferry handoff --bundle ./bundle.ferry --output ./SESSION.md --passphrase "your passphrase"
# Recipient mode: --identity "<recipient private key base64>"

# Validate the manifest against the schema
ai-context-ferry validate --manifest ./exported/asset-manifest.json
```

### Platform disk layouts (built from public docs + known structures)
- **Claude Code**: `~/.claude/{CLAUDE.md, settings.json, skills/, commands/, agents/, projects/<encoded-path>/<uuid>.jsonl, history.jsonl}` plus `~/.claude.json` (projects + MCP).
- **Codex**: `~/.codex/{AGENTS.md, config.toml, rules/, history.jsonl, sessions/**/rollout-*.jsonl, auth.json (tokens — must redact), state_5.sqlite}`.
- **WorkBuddy**: `~/.workbuddy/{MEMORY.md, USER.md, SOUL.md, IDENTITY.md (profile memory), memory/*.md (project memory), skills/ (reusable assets), settings.json (may contain tokens), workbuddy.db (automations, exported as redacted JSON snapshots), projects/ (index only)}`. This adapter is self-built for this project; there is no external OSS to copy from.

### Quick start
```bash
pip install -e .
ai-context-ferry list-platforms
ai-context-ferry export --platform codex --account "" --out ./exported
ai-context-ferry package --input ./exported --output ./bundle.ferry --passphrase "pw"
ai-context-ferry handoff --bundle ./bundle.ferry --output ./SESSION.md --passphrase "pw"
```

## License
MIT
