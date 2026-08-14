# REFERENCES · 引用与借鉴来源

本项目遵循「能抄就抄、必要才自造、引用必标注」的原则。下方列明所有**复用、借鉴或受过启发的开源项目与方法**，并标注其许可与具体借鉴点。

> 说明：本项目的**代码均为原创实现**，未直接复制他人源码；下列项目主要提供**范式、结构设计与工程方法论**层面的借鉴。加密部分直接依赖 `cryptography` 库（见「直接依赖」），属于合规复用。

---

## 一、直接依赖（代码级复用，合法依赖）

| 项目 | 许可 | 用途 |
|------|------|------|
| [PyCA `cryptography`](https://github.com/pyca/cryptography) | Apache-2.0 / BSD-3 | AES-256-GCM、Argon2id（密钥派生）、X25519（密钥协商）等所有加密原语 |
| [`jinja2`](https://github.com/pallets/jinja) | BSD-3 | 渲染 `SESSION.md` 交接文档模板 |
| [`jsonschema`](https://github.com/python-jsonschema/jsonschema) | MIT | 校验 `asset-manifest` 是否符合 v2.0.0 schema |

## 二、范式 / 结构借鉴（未复制代码，仅借鉴设计）

| 项目 | 许可 | 借鉴点 | 本项目的对应实现 |
|------|------|--------|------------------|
| [mick-gsk/DevCD](https://github.com/mick-gsk/DevCD) · `devcd-agent-handoff-packet.schema.json` | 以其仓库 LICENSE 为准 | **agent 交接包**结构：`do_not_repeat` / `blockers` / `confidence` / `withheld_context` 等机读交接语义；以及对"应交接/不应交接"的治理思路 | `spec/asset-manifest.schema.json` 的 `handoff` 块（脱敏治理、置信度、阻塞项、下一步建议）；`ManifestBuilder.withheld()/set_policy()/set_blocker()` |
| [FiloSottile/age](https://github.com/FiloSottile/age) | MIT（以其仓库 LICENSE 为准） | **双模式加密信封**设计哲学：`passphrase`（口令派生）与 `recipient`（X25519 公钥）两种模式并存，信封自描述、可调试 | `src/handoff_kit/crypto.py` 的 `ferry-crypt` 信封（passphrase + recipient 双模式，自描述 JSON 信封） |
| [ha0xin/chatgpt-context-export](https://github.com/ha0xin/chatgpt-context-export)（62★） | MIT | **AI 上下文导出**的产品范式：把对话/记忆/配置打包迁移的思路 | 整体产品方向（多平台上下文导出），以及"先有导出、再有标准化包"的工作流 |
| [climux](https://github.com/) / [inkwell](https://github.com/) / [houyanchao](https://github.com/) | 以其仓库 LICENSE 为准 | 同类**上下文/会话导出**工具的邻接参考，用于确认"导出 → 标准化 → 交接"这一需求真实存在且未被单一工具垄断 | 竞品格局判断（见定位报告），确认差异化空间 |

## 三、方法论来源（非代码）

- **Argon2id**：2015 年 Password Hashing Competition 冠军算法（RFC 9106）。作为口令模式密钥派生的业界最佳实践，抗 GPU/ASIC 暴力破解。
- **AES-256-GCM**：NIST 推荐的 AEAD 原语，提供机密性 + 完整性（防篡改）。
- **X25519 ECDH + HKDF-SHA256**：用于 recipient 模式的密钥协商（与 age 的 X25519 思路一致），无需共享口令即可安全交接到另一账号/人。
- **平台磁盘布局**：Claude Code 的 `~/.claude/{CLAUDE.md,settings,projects/<encoded>/<uuid>.jsonl}` 与 Codex 的 `~/.codex/{AGENTS.md,config.toml,sessions/**/rollout-*.jsonl,auth.json}` 结构，依据各自**公开文档与社区整理**构建（用户已授权"公开文档 + 已知结构先构建"）。

---

## 四、差异化声明（为什么不直接 fork 上述项目）

上述项目各自只覆盖「导出」或「加密」的某一环：
- DevCD 偏 agent 交接语义，不提供多平台适配器与加密资产包；
- age 是通用加密工具，不感知 AI 上下文资产；
- ha0xin/climux/inkwell/houyanchao 是单一平台或单一环节的导出器。

**本项目的护城河 = 三合一**：多平台适配器（Claude Code / Codex / …）＋ 标准化加密资产包（JSON Schema v2.0.0）＋ 自动 `SESSION.md` 交接文档。开源界目前**无人把这三件事合成一个 CLI**。这正是本项目的差异化定位。

---

## 五、未引入的实现取舍

- 未自造加密算法：坚决复用 `cryptography` 的验证原语，不引入任何 homegrown crypto。
- 未复制 DevCD / age 的源码：仅借鉴其 schema 结构与信封设计哲学，所有实现独立编写，便于 MIT 许可下的再分发。
- Hermes 适配器：按用户指示保留**骨架**（平台指代待确认），未假定其数据格式，故未借鉴任何第三方实现。
- **WorkBuddy 适配器为项目自研（原创）**：`~/.workbuddy` 的布局（画像记忆 MEMORY/USER/SOUL/IDENTITY、`memory/*.md`、可复用 `skills/`、`settings.json`、自动化数据库 `workbuddy.db` 的 `automations` 表、轻量 `projects/` 索引）来自本机运行环境真实结构，**无外部开源可抄**，属于"迫不得已自造"的差异化一环；其代码（除 `cryptography`/`jinja2`/`jsonschema` 依赖外）均为原创。
