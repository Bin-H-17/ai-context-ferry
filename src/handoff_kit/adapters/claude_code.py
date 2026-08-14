"""Claude Code 适配器。

采集 Claude Code 在磁盘上的上下文资产：
- 全局记忆 ``~/.claude/CLAUDE.md``
- 设置 ``settings.json`` / ``settings.local.json``
- 可复用资产 ``skills/`` ``commands/`` ``agents/``
- 历史对话 ``projects/<encoded-path>/<uuid>.jsonl``（对话是价值最高的部分）
- 命令历史 ``history.jsonl``
- 账号级注册 ``~/.claude.json``（projects + MCP，MCP 含令牌，需脱敏）

平台磁盘布局参考 Anthropic 官方文档与社区整理：
- 项目路径编码：去掉前导 ``/``，``/`` → ``-``，整体前缀 ``-``
  （如 ``/path/to/project`` → ``-path-to-project``）。
- 该布局为公开文档结构，本适配器按"公开文档 + 已知结构"构建（用户授权）。
"""

from __future__ import annotations

import hashlib
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .base import Asset, BaseAdapter, ManifestBuilder, privacy_mask, sha256_of

# 文本读取上限，超过则原样拷贝不做行内脱敏
_MAX_REDACT_BYTES = 50 * 1024 * 1024


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _decode_project(encoded: str) -> str:
    """把 Claude 编码后的项目目录名还原成可读路径。"""
    s = encoded
    if s.startswith("-"):
        s = s[1:]
    return s.replace("-", "/")


class ClaudeCodeAdapter(BaseAdapter):
    platform = "claude_code"

    # ---- 对外接口 ----
    def export(self, account: str = "", out_dir: str = "") -> Dict[str, Any]:
        home = self._resolve_home(account)
        claude_dir = home / ".claude"
        claude_json = home / ".claude.json"
        export_root = Path(out_dir)
        (export_root / "claude_code").mkdir(parents=True, exist_ok=True)

        mb = ManifestBuilder("claude_code", privacy_mask(str(home)))

        # 1) 全局记忆
        for fname in ("CLAUDE.md",):
            p = claude_dir / fname
            if p.exists():
                self._ingest_text(
                    p, export_root, "claude_code", mb,
                    asset_type="memory", name=f"全局记忆 {fname}",
                    importance="high", relevance=0.85,
                )

        # 2) 设置
        for fname in ("settings.json", "settings.local.json"):
            p = claude_dir / fname
            if p.exists():
                self._ingest_text(
                    p, export_root, "claude_code", mb,
                    asset_type="config", name=f"设置 {fname}",
                    importance="medium", relevance=0.6,
                )

        # 3) 可复用资产：skills / commands / agents
        for dname, atype, imp in (
            ("skills", "skill", "medium"),
            ("commands", "skill", "medium"),
            ("agents", "config", "medium"),
        ):
            d = claude_dir / dname
            if d.is_dir():
                self._ingest_dir(d, export_root, "claude_code", mb,
                                 asset_type=atype, importance=imp,
                                 label=dname)

        # 4) 历史对话（价值最高）
        projects_dir = claude_dir / "projects"
        if projects_dir.is_dir():
            for enc in sorted(projects_dir.iterdir()):
                if not enc.is_dir():
                    continue
                project_label = _decode_project(enc.name)
                for jf in sorted(enc.glob("*.jsonl")):
                    self._ingest_text(
                        jf, export_root, "claude_code/projects", mb,
                        asset_type="conversation",
                        name=f"对话 {project_label}/{jf.stem}",
                        importance="high", relevance=0.9,
                        sub=enc.name,
                    )

        # 5) 命令历史
        hist = claude_dir / "history.jsonl"
        if hist.exists():
            self._ingest_text(
                hist, export_root, "claude_code", mb,
                asset_type="conversation", name="命令历史 history.jsonl",
                importance="low", relevance=0.3,
            )

        # 6) 账号级注册（projects + MCP，含令牌 → 需重授权）
        if claude_json.exists():
            self._ingest_text(
                claude_json, export_root, "claude_code", mb,
                asset_type="config", name="项目与 MCP 注册 (.claude.json)",
                importance="medium", relevance=0.5, reauth_required=True,
            )

        # ---- 凭据抽取汇总 + handoff 治理 ----
        inv = self._dump_secrets(str(export_root))
        withheld = set(inv.get("by_category", {}).keys())
        if withheld:
            mb.set_policy(
                allowed=True,
                operation="export+extract-secrets",
                reason="检出的敏感凭据已抽取进加密保险库，原文仅留引用占位",
                withheld_data_classes=sorted(withheld),
                withheld_sources=["claude_code"],
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
            if (cand / ".claude").is_dir():
                return cand
        return Path.home()

    def _ingest_text(
        self,
        src: Path,
        export_root: Path,
        prefix: str,
        mb: ManifestBuilder,
        *,
        asset_type: str,
        name: str,
        importance: str,
        relevance: float,
        reauth_required: bool = False,
        sub: Optional[str] = None,
    ) -> None:
        rel_parts = [prefix]
        if sub is not None:
            rel_parts.append(sub)
        rel_parts.append(src.name)
        rel_str = "/".join(rel_parts)

        size = src.stat().st_size
        if size > _MAX_REDACT_BYTES:
            dst = export_root / rel_str
            dst.parent.mkdir(parents=True, exist_ok=True)
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
        self,
        d: Path,
        export_root: Path,
        prefix: str,
        mb: ManifestBuilder,
        *,
        asset_type: str,
        importance: str,
        label: str,
    ) -> None:
        for f in sorted(d.rglob("*")):
            if not f.is_file():
                continue
            rel_parts = [prefix, d.name, str(f.relative_to(d))]
            rel_str = "/".join(rel_parts)
            try:
                mb.add(self._redact_collect_text(
                    rel_str, str(f), str(export_root), asset_type,
                    f"{label}/{f.relative_to(d)}", importance, 0.6,
                    reauth_required=False,
                ))
            except (UnicodeDecodeError, OSError):
                dst = export_root / rel_str
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dst)
                mb.add(self._mk_asset(
                    rel_str, dst, asset_type,
                    name=f"{label}/{f.relative_to(d)}",
                    importance=importance, relevance=0.6,
                    reauth_required=False,
                    notes="二进制/非常规文件，原样拷贝",
                ))

    def _mk_asset(
        self, rel_str: str, dst: Path, asset_type: str, name: str,
        importance: str, relevance: float, reauth_required: bool,
        notes: Optional[str],
    ) -> Asset:
        aid = "cc-" + hashlib.md5(rel_str.encode("utf-8")).hexdigest()[:12]
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
