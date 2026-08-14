"""OpenAI Codex 适配器。

采集 Codex 在磁盘上的上下文资产（位于 ``~/.codex/``）：
- 全局记忆 ``AGENTS.md`` / ``AGENTS.override.md``
- 配置 ``config.toml``、``rules/``
- 历史对话 ``history.jsonl``
- 会话转录 ``sessions/YYYY/MM/DD/rollout-*.jsonl``（价值最高；新版首行为 session_meta）
- 鉴权 ``auth.json``（含令牌，必须脱敏且标记需重授权）
- 状态库 ``state_5.sqlite``（原样拷贝，备注）

磁盘布局与转录 schema 参考 OpenAI Codex 公开文档与社区整理：
- 转录 JSONL 存在两种 schema：
  * 旧版：每行 ``response_item`` / ``event_msg``
  * 新版：首行 ``session_meta``，其后 ``response_item`` / ``turn.*`` 事件
  * 通过 ``session_meta.source`` 区分 cli 与 subagent。
- 该结构为公开文档结构，本适配器按"公开文档 + 已知结构"构建（用户授权）。
"""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .base import Asset, BaseAdapter, ManifestBuilder, privacy_mask, sha256_of

_MAX_REDACT_BYTES = 50 * 1024 * 1024


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_session_meta(src: Path) -> Dict[str, str]:
    """读取会话 JSONL 首行，提取 session_meta（若存在）。"""
    try:
        with open(src, "r", encoding="utf-8", errors="replace") as f:
            first = f.readline().strip()
        if not first:
            return {}
        obj = json.loads(first)
        if isinstance(obj, dict) and obj.get("type") == "session_meta":
            return {k: str(v) for k, v in obj.items() if k != "type"}
    except (OSError, json.JSONDecodeError):
        pass
    return {}


class CodexAdapter(BaseAdapter):
    platform = "codex"

    def export(self, account: str = "", out_dir: str = "") -> Dict[str, Any]:
        home = self._resolve_home(account)
        codex_dir = home / ".codex"
        export_root = Path(out_dir)
        (export_root / "codex").mkdir(parents=True, exist_ok=True)

        mb = ManifestBuilder("codex", privacy_mask(str(home)))

        # 1) 全局记忆
        for fname, imp in (("AGENTS.md", "high"), ("AGENTS.override.md", "medium")):
            p = codex_dir / fname
            if p.exists():
                self._ingest_text(
                    p, export_root, "codex", mb,
                    asset_type="memory", name=f"全局记忆 {fname}",
                    importance=imp, relevance=0.85,
                )

        # 2) 配置
        cfg = codex_dir / "config.toml"
        if cfg.exists():
            self._ingest_text(
                cfg, export_root, "codex", mb,
                asset_type="config", name="配置 config.toml",
                importance="medium", relevance=0.6,
            )

        # 3) 规则
        rules = codex_dir / "rules"
        if rules.is_dir():
            self._ingest_dir(rules, export_root, "codex", mb,
                             asset_type="config", importance="medium",
                             label="rules")

        # 4) 历史
        hist = codex_dir / "history.jsonl"
        if hist.exists():
            self._ingest_text(
                hist, export_root, "codex", mb,
                asset_type="conversation", name="历史 history.jsonl",
                importance="low", relevance=0.3,
            )

        # 5) 会话转录（价值最高）
        sessions_dir = codex_dir / "sessions"
        if sessions_dir.is_dir():
            for jf in sorted(sessions_dir.rglob("rollout-*.jsonl")):
                meta = _parse_session_meta(jf)
                source = meta.get("source", "cli")
                session_id = meta.get("session_id", jf.stem)
                rel_str = "codex/sessions/" + str(jf.relative_to(sessions_dir)).replace("\\", "/")
                self._ingest_rel(rel_str, jf, export_root, mb,
                                asset_type="conversation",
                                name=f"会话 {source}/{session_id}",
                                importance="high", relevance=0.9)

        # 6) 鉴权（含令牌，必须脱敏 + 重授权）
        auth = codex_dir / "auth.json"
        if auth.exists():
            self._ingest_text(
                auth, export_root, "codex", mb,
                asset_type="config", name="鉴权 auth.json",
                importance="medium", relevance=0.4, reauth_required=True,
            )

        # 7) 状态库（sqlite，原样拷贝）
        state = codex_dir / "state_5.sqlite"
        if state.exists():
            dst = export_root / "codex" / "state_5.sqlite"
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(state, dst)
            mb.add(self._mk_asset(
                "codex/state_5.sqlite", dst, "config",
                name="状态库 state_5.sqlite",
                importance="low", relevance=0.2, reauth_required=False,
                notes="SQLite 状态库，原样拷贝（未经解析）",
            ))

        # ---- 凭据抽取汇总 + handoff 治理 ----
        inv = self._dump_secrets(str(export_root))
        withheld = set(inv.get("by_category", {}).keys())
        if withheld:
            mb.set_policy(
                allowed=True,
                operation="export+extract-secrets",
                reason="检出的敏感凭据已抽取进加密保险库，原文仅留引用占位",
                withheld_data_classes=sorted(withheld),
                withheld_sources=["codex"],
            )
            for c in sorted(withheld):
                mb.withheld(
                    c,
                    "凭据已抽取并单独加密，接收方凭口令/私钥可恢复",
                    f"原文以 «SECRET:{c}:*» 占位，值未明文外泄",
                )
        mb.set_confidence(0.9 if mb._assets else 0.2)
        manifest = mb.build()
        manifest["secret_inventory"] = inv
        return manifest

    # ---- 内部工具 ----
    def _resolve_home(self, account: str) -> Path:
        if account:
            cand = Path(account).expanduser()
            if cand.is_dir():
                return cand
            if (cand / ".codex").is_dir():
                return cand
        return Path.home()

    def _ingest_text(
        self, src: Path, export_root: Path, prefix: str, mb: ManifestBuilder,
        *, asset_type: str, name: str, importance: str, relevance: float,
        reauth_required: bool = False,
    ) -> None:
        rel_str = f"{prefix}/{src.name}"
        self._write(src, rel_str, export_root, mb,
                    asset_type, name, importance, relevance, reauth_required)

    def _ingest_rel(
        self, rel_str: str, src: Path, export_root: Path, mb: ManifestBuilder,
        *, asset_type: str, name: str, importance: str, relevance: float,
        reauth_required: bool = False,
    ) -> None:
        self._write(src, rel_str, export_root, mb,
                    asset_type, name, importance, relevance, reauth_required)

    def _write(
        self, src: Path, rel_str: str, export_root: Path, mb: ManifestBuilder,
        asset_type: str, name: str, importance: str, relevance: float,
        reauth_required: bool,
    ) -> None:
        dst = export_root / rel_str
        dst.parent.mkdir(parents=True, exist_ok=True)
        size = src.stat().st_size
        if size > _MAX_REDACT_BYTES:
            shutil.copy2(src, dst)
            mb.add(self._mk_asset(rel_str, dst, asset_type, name, importance,
                                  relevance, reauth_required,
                                  notes="大文件(>50MB)原样拷贝，未做行内脱敏"))
            return
        mb.add(self._redact_collect_text(
            rel_str, str(src), str(export_root), asset_type, name,
            importance, relevance, reauth_required,
        ))

    def _ingest_dir(
        self, d: Path, export_root: Path, prefix: str, mb: ManifestBuilder,
        *, asset_type: str, importance: str, label: str,
    ) -> None:
        for f in sorted(d.rglob("*")):
            if not f.is_file():
                continue
            rel_str = f"{prefix}/{d.name}/{f.relative_to(d)}".replace("\\", "/")
            dst = export_root / rel_str
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                mb.add(self._redact_collect_text(
                    rel_str, str(f), str(export_root), asset_type,
                    f"{label}/{f.relative_to(d)}", importance, 0.6,
                    reauth_required=False,
                ))
            except (UnicodeDecodeError, OSError):
                shutil.copy2(f, dst)
                mb.add(self._mk_asset(
                    rel_str, dst, asset_type,
                    name=f"{label}/{f.relative_to(d)}",
                    importance=importance, relevance=0.6,
                    reauth_required=False, notes="二进制/非常规文件，原样拷贝",
                ))

    def _mk_asset(
        self, rel_str: str, dst: Path, asset_type: str, name: str,
        importance: str, relevance: float, reauth_required: bool,
        notes: Optional[str],
    ) -> Asset:
        aid = "cx-" + hashlib.md5(rel_str.encode("utf-8")).hexdigest()[:12]
        return Asset(
            asset_id=aid,
            asset_type=asset_type,
            name=name,
            importance=importance,
            transferable=True,
            path=rel_str,
            size_bytes=dst.stat().st_size,
            last_modified=_iso(dst.stat().st_mtime),
            relevance=relevance,
            reauth_required=reauth_required,
            checksum=sha256_of(str(dst)),
            notes=notes,
        )
