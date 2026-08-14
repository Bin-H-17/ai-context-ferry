"""Cursor 编辑器适配器（防御式、只读）。

Cursor 把聊天 / Composer 历史存在本地 SQLite（``state.vscdb``），不依赖云端：
- 基础目录（按平台）：
  * Windows: ``%APPDATA%\\Cursor\\User``
  * macOS:   ``~/Library/Application Support/Cursor/User``
  * Linux:   ``~/.config/Cursor/User``
- ``settings.json``、``snippets/``：用户设置与代码片段。
- ``globalStorage/state.vscdb``：全局聊天内容（``cursorDiskKV`` 表，键 ``bubbleId::`` /
  ``composer.composerData``）。
- ``workspaceStorage/<hash>/state.vscdb`` + ``workspace.json``：每个项目的工作区数据，
  ``workspace.json`` 记录真实项目路径。

解析策略（只读、``?mode=ro``，绝不写入原库）：
- 遍历每个 ``state.vscdb``，从 ``cursorDiskKV`` 抽取 ``bubbleId::`` 气泡 JSON，
  提取 ``text`` / 思考块；按 ``composerId`` 归并到对话。
- 读取 ``workspace.json`` 还原项目路径，作为资产名。

参考：社区对 Cursor state.vscdb 结构的逆向整理（cursorDiskKV / composer.composerData）。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import Asset, BaseAdapter, ManifestBuilder, privacy_mask, sha256_of

# 平台基础目录（相对用户主目录）
_CURSOR_REL = {
    "windows": "AppData/Roaming/Cursor/User",
    "darwin": "Library/Application Support/Cursor/User",
    "linux": ".config/Cursor/User",
}


def _iso(ts: Optional[str]) -> Optional[str]:
    if not ts:
        return None
    return ts  # Cursor 已是 ISO 字符串


def _bubble_text(bubble: Dict[str, Any]) -> str:
    """从 Cursor 气泡 JSON 提取可读文本（用户/助手消息 + 思考块）。"""
    parts: List[str] = []
    text = bubble.get("text")
    if isinstance(text, str) and text.strip():
        parts.append(text)
    # 思考过程（如有）
    thinking = bubble.get("allThinkingBlocks")
    if isinstance(thinking, list):
        for blk in thinking:
            if isinstance(blk, dict) and blk.get("text"):
                parts.append(f"[thinking] {blk['text']}")
    # 代码块（如有）
    code = bubble.get("codeBlocks")
    if isinstance(code, list):
        for cb in code:
            if isinstance(cb, dict) and cb.get("code"):
                parts.append(f"```\n{cb['code']}\n```")
    return "\n\n".join(parts)


class CursorAdapter(BaseAdapter):
    platform = "cursor"

    def export(self, account: str = "", out_dir: str = "") -> Dict[str, Any]:
        base = self._resolve(account)
        export_root = Path(out_dir)
        (export_root / "cursor").mkdir(parents=True, exist_ok=True)

        mb = ManifestBuilder("cursor", privacy_mask(str(base)))

        # 1) 设置 + 片段
        settings = base / "settings.json"
        if settings.exists():
            self._ingest_text(settings, export_root, "cursor", mb,
                              asset_type="config", name="设置 settings.json",
                              importance="medium", relevance=0.6, reauth_required=True)
        snippets = base / "snippets"
        if snippets.is_dir():
            self._ingest_dir(snippets, export_root, "cursor", mb,
                             asset_type="config", importance="medium", label="snippets")

        # 2) 全局聊天（globalStorage/state.vscdb）
        gvsc = base / "globalStorage" / "state.vscdb"
        if gvsc.exists():
            self._parse_vscdb(gvsc, export_root, mb, label="global")

        # 3) 每个工作区（workspaceStorage/<hash>/state.vscdb + workspace.json）
        ws_root = base / "workspaceStorage"
        if ws_root.is_dir():
            for ws in sorted(ws_root.iterdir()):
                if not ws.is_dir():
                    continue
                vsc = ws / "state.vscdb"
                project_path = "(未知项目)"
                wj = ws / "workspace.json"
                if wj.exists():
                    try:
                        project_path = json.loads(
                            wj.read_text(encoding="utf-8", errors="replace")
                        ).get("folder", project_path)
                    except (OSError, json.JSONDecodeError):
                        pass
                if vsc.exists():
                    self._parse_vscdb(
                        vsc, export_root, mb, label=f"workspace:{project_path}"
                    )

        inv = self._dump_secrets(str(export_root))
        withheld = set(inv.get("by_category", {}).keys())
        if withheld:
            mb.set_policy(
                allowed=True,
                operation="export+extract-secrets",
                reason="检出的敏感凭据已抽取进加密保险库，原文仅留引用占位",
                withheld_data_classes=sorted(withheld),
                withheld_sources=["cursor"],
            )
        mb.set_confidence(0.85 if mb._assets else 0.2)
        manifest = mb.build()
        manifest["secret_inventory"] = inv
        return manifest

    # ---- 内部工具 ----
    def _resolve(self, account: str) -> Path:
        if account:
            p = Path(account).expanduser()
            if p.is_dir():
                return p
        home = Path.home()
        import sys
        plat = "windows" if sys.platform.startswith("win") else (
            "darwin" if sys.platform == "darwin" else "linux"
        )
        cand = home / _CURSOR_REL[plat]
        return cand if cand.is_dir() else (home / ".cursor")

    def _parse_vscdb(self, vsc: Path, export_root: Path, mb: ManifestBuilder, label: str) -> None:
        """只读解析一个 state.vscdb，抽取聊天气泡并归一为对话资产。"""
        try:
            conn = sqlite3.connect(f"file:{vsc}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
        except (sqlite3.Error, OSError):
            return

        bubbles: Dict[str, List[Dict[str, Any]]] = {}
        try:
            candidate_tables = [t for t in ("cursorDiskKV", "ItemTable") if t in tables]
            for tname in candidate_tables:
                for row in conn.execute(
                    f"SELECT key, value FROM {tname} "
                    f"WHERE key LIKE 'bubbleId::%' OR key LIKE 'composer.composerData' "
                    f"OR key LIKE 'workbench.panel.composer%'"
                ):
                    key, value = row["key"], row["value"]
                    if not isinstance(value, str):
                        continue
                    try:
                        obj = json.loads(value)
                    except (json.JSONDecodeError, TypeError):
                        continue
                    if not isinstance(obj, dict):
                        continue
                    if key.startswith("bubbleId::"):
                        composer = obj.get("composerId") or "default"
                        bubbles.setdefault(composer, []).append(obj)
                    else:  # composer.composerData：会话元数据，轻量登记
                        mb.add(self._mk_asset(
                            f"cursor/composer/{label}.json",
                            self._write_json(export_root, f"cursor/composer/{label}.json",
                                             {"composer_meta": obj, "source": str(vsc)}),
                            "conversation",
                            f"Composer 元数据 {label}",
                            "low", 0.3, False,
                            notes="Cursor composer 元数据（轻量）",
                        ))
        except sqlite3.Error:
            pass
        finally:
            conn.close()

        if not bubbles:
            return

        # 归并每个 composer 的气泡为一份对话文档
        for composer_id, items in bubbles.items():
            items.sort(key=lambda b: b.get("createdAt") or "")
            lines: List[str] = [f"# Cursor 对话（{label} / composer {composer_id[:8]}）", ""]
            for b in items:
                role = "user" if b.get("type") == 1 else (
                    "assistant" if b.get("type") == 2 else "system"
                )
                txt = _bubble_text(b)
                if not txt:
                    continue
                lines.append(f"## {role}")
                lines.append("")
                lines.append(txt)
                lines.append("")
            md = "\n".join(lines)
            rel_str = f"cursor/conversations/{label}/{composer_id[:12]}.md"
            rel_str = rel_str.replace(":", "_")
            mb.add(self._redact_collect_text_inline(
                rel_str, md, str(export_root), mb, f"对话 {label}/{composer_id[:8]}"
            ))

    def _write_json(self, export_root: Path, rel_str: str, obj: Any) -> Path:
        dst = export_root / rel_str
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
        return dst

    def _redact_collect_text_inline(
        self, rel_str: str, text: str, export_root: str, mb: ManifestBuilder, title: str
    ) -> Asset:
        from ..redact import extract_secrets

        sanitized, records = extract_secrets(text)
        for r in records:
            r.source_hint = rel_str
        self._secrets.extend(records)
        dst = Path(export_root) / rel_str
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(sanitized, encoding="utf-8")
        return self._mk_asset(rel_str, dst, "conversation", f"对话 {title}",
                              "high", 0.9, False, None)

    def _ingest_text(self, src: Path, export_root: Path, prefix: str, mb: ManifestBuilder,
                     *, asset_type: str, name: str, importance: str, relevance: float,
                     reauth_required: bool = False) -> None:
        rel_str = f"{prefix}/{src.name}"
        mb.add(self._redact_collect_text(
            rel_str, str(src), str(export_root), asset_type, name,
            importance, relevance, reauth_required,
        ))

    def _ingest_dir(self, d: Path, export_root: Path, prefix: str, mb: ManifestBuilder,
                    *, asset_type: str, importance: str, label: str) -> None:
        import shutil
        for f in sorted(d.rglob("*")):
            if not f.is_file():
                continue
            rel_str = f"{prefix}/{d.name}/{f.relative_to(d)}".replace("\\", "/")
            dst = export_root / rel_str
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                mb.add(self._redact_collect_text(
                    rel_str, str(f), str(export_root), asset_type,
                    f"{label}/{f.relative_to(d)}", importance, 0.6, False,
                ))
            except (UnicodeDecodeError, OSError):
                shutil.copy2(f, dst)
                mb.add(self._mk_asset(
                    rel_str, dst, asset_type, f"{label}/{f.relative_to(d)}",
                    importance, 0.6, False, notes="二进制/非常规文件，原样拷贝",
                ))

    def _mk_asset(self, rel_str: str, dst: Path, asset_type: str, name: str,
                  importance: str, relevance: float, reauth_required: bool,
                  notes: Optional[str]) -> Asset:
        aid = "cu-" + hashlib.md5(rel_str.encode("utf-8")).hexdigest()[:12]
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
