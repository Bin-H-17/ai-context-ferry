"""OpenAI ChatGPT 适配器。

采集 ChatGPT 的上下文资产。由于 ChatGPT 桌面端的本地存储是 LevelDB / SQLite
（且随版本变动、本机未必安装），最稳健、可移植的适配目标是
**OpenAI 官方数据导出格式**（用户在 chat.openai.com → Settings → Data controls →
Export 后得到的 ``conversations.json`` 或 ``conversations/<uuid>.json``）。

该格式每条对话是一个 JSON 对象：
- ``title`` / ``create_time`` / ``update_time``
- ``mapping``：节点字典，节点 ``message`` 含 ``author.role`` 与 ``content``（parts 或文本）

适配器会把对话逐条抽取为可读的 markdown，并走统一的凭据抽取流程。

候选根目录（按优先级探测，Windows 为主）：
- ``%APPDATA%\\Roaming\\OpenAI\\ChatGPT``
- ``%LOCALAPPDATA%\\Packages\\OpenAI.ChatGPT-Desktop_*\\LocalCache\\Roaming\\ChatGPT``
- ``~/.chatgpt``
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import Asset, BaseAdapter, ManifestBuilder, privacy_mask, sha256_of

# 候选根目录（相对用户目录的片段）；解析时按存在性探测。
_CANDIDATE_REL = (
    "AppData/Roaming/OpenAI/ChatGPT",
    "AppData/Local/Packages/OpenAI.ChatGPT-Desktop_/LocalCache/Roaming/ChatGPT",
)


def _iso(ts: Optional[float]) -> Optional[str]:
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _content_to_text(content: Any) -> str:
    """把 ChatGPT content 字段（可能是 str 或 {type, parts:[...]}）归一为文本。"""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        parts = content.get("parts")
        if isinstance(parts, list):
            return "\n".join(str(p) for p in parts if isinstance(p, (str, int, float)))
        return str(content.get("text", ""))
    return str(content)


class ChatgptAdapter(BaseAdapter):
    platform = "chatgpt"

    def export(self, account: str = "", out_dir: str = "") -> Dict[str, Any]:
        root = self._resolve(account)
        export_root = Path(out_dir)
        (export_root / "chatgpt").mkdir(parents=True, exist_ok=True)

        mb = ManifestBuilder("chatgpt", privacy_mask(str(root)))

        # 1) 官方导出：单个 conversations.json（大数组）
        big = root / "conversations.json"
        if big.exists():
            self._ingest_export_file(big, export_root, mb)

        # 2) 官方导出：conversations/ 目录（每对话一个文件）
        conv_dir = root / "conversations"
        if conv_dir.is_dir():
            for jf in sorted(conv_dir.glob("*.json")):
                self._ingest_conversation_file(jf, export_root, mb)

        if not (big.exists() or conv_dir.is_dir()):
            mb.set_confidence(0.1)
            manifest = mb.build()
            manifest["secret_inventory"] = {
                "total": 0, "encrypted": False, "by_category": {}, "examples": []
            }
            manifest["_warning"] = (
                "未找到 ChatGPT 官方导出文件（conversations.json / conversations/）。"
                "请在 chat.openai.com → Settings → Data controls → Export 后，"
                "把导出目录作为 --account 传入。"
            )
            return manifest

        inv = self._dump_secrets(str(export_root))
        withheld = set(inv.get("by_category", {}).keys())
        if withheld:
            mb.set_policy(
                allowed=True,
                operation="export+extract-secrets",
                reason="检出的敏感凭据已抽取进加密保险库，原文仅留引用占位",
                withheld_data_classes=sorted(withheld),
                withheld_sources=["chatgpt"],
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
        for rel in _CANDIDATE_REL:
            cand = home / rel
            if cand.is_dir():
                return cand
        return home / ".chatgpt"

    def _ingest_export_file(self, big: Path, export_root: Path, mb: ManifestBuilder) -> None:
        import json

        try:
            data = json.loads(big.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            return
        if isinstance(data, list):
            for conv in data:
                if isinstance(conv, dict):
                    self._emit_conversation(conv, export_root, mb)

    def _ingest_conversation_file(self, jf: Path, export_root: Path, mb: ManifestBuilder) -> None:
        import json

        try:
            conv = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            return
        if isinstance(conv, dict):
            self._emit_conversation(conv, export_root, mb)

    def _emit_conversation(self, conv: Dict[str, Any], export_root: Path, mb: ManifestBuilder) -> None:
        title = conv.get("title") or "(无标题)"
        title_safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in title)[:40]
        cid = conv.get("id") or title_safe
        rel_str = f"chatgpt/conversations/{cid}.md"
        dst = export_root / rel_str
        dst.parent.mkdir(parents=True, exist_ok=True)

        lines: List[str] = [f"# {title}", ""]
        mapping = conv.get("mapping") or {}
        # 按 create_time 排序节点，尽量还原时间线
        nodes = []
        for node in mapping.values():
            if not isinstance(node, dict):
                continue
            msg = node.get("message")
            if not isinstance(msg, dict):
                continue
            ts = msg.get("create_time")
            role = (msg.get("author") or {}).get("role")
            text = _content_to_text(msg.get("content"))
            if not text:
                continue
            nodes.append((ts or 0, role, text))
        nodes.sort(key=lambda x: x[0])
        for _ts, role, text in nodes:
            lines.append(f"## {role or 'unknown'}")
            lines.append("")
            lines.append(text)
            lines.append("")

        md = "\n".join(lines)
        mb.add(self._redact_collect_text_inline(
            rel_str, md, str(export_root), mb, title,
        ))

    def _redact_collect_text_inline(
        self, rel_str: str, text: str, export_root: str, mb: ManifestBuilder, title: str
    ) -> Asset:
        """对已知文本（非磁盘文件）做抽取+收集，并登记 Asset。"""
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

    def _mk_asset(
        self, rel_str: str, dst: Path, asset_type: str, name: str,
        importance: str, relevance: float, reauth_required: bool,
        notes: Optional[str],
    ) -> Asset:
        aid = "cg-" + hashlib.md5(rel_str.encode("utf-8")).hexdigest()[:12]
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
