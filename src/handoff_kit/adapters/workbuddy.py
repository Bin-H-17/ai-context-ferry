"""WorkBuddy 适配器（自研平台，使用运行环境真实结构）。

采集 WorkBuddy 在磁盘上的上下文资产，便于把"个人 AI 工作台"整体迁移 / 交接：
- 个人画像记忆 ``MEMORY.md`` ``USER.md`` ``SOUL.md`` ``IDENTITY.md``
- 项目级记忆 ``memory/*.md``
- 可复用资产 ``skills/``（含 SKILL.md 与脚本）
- 工作设置 ``settings.json``（可能含令牌 → 脱敏 + 重授权）
- 自动化 ``workbuddy.db`` 中的 ``automations`` 表（导出为脱敏 JSON 快照）
- 项目索引 ``projects/`` 的轻量清单（不复制庞大的会话数据）

数据来源为本机 ``~/.workbuddy``（或 ``--account`` 指向的等价目录）。
本适配器为 ai-context-ferry 自研，无外部开源可抄，属于"迫不得已自造"的差异化一环。
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .base import Asset, BaseAdapter, ManifestBuilder, privacy_mask, sha256_of
from ..redact import extract_secrets

# 文本读取上限，超过则原样拷贝不做行内脱敏
_MAX_REDACT_BYTES = 50 * 1024 * 1024

# 判定一个目录是否为 WorkBuddy 根的标志文件/目录
_WB_MARKERS = ("skills", "memory", "workbuddy.db", "MEMORY.md", "settings.json")


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class WorkbuddyAdapter(BaseAdapter):
    platform = "workbuddy"

    # ---- 对外接口 ----
    def export(self, account: str = "", out_dir: str = "") -> Dict[str, Any]:
        wb_dir = self._resolve(account)
        export_root = Path(out_dir)
        (export_root / "workbuddy").mkdir(parents=True, exist_ok=True)

        mb = ManifestBuilder("workbuddy", privacy_mask(str(wb_dir)))

        # 1) 个人画像记忆
        for fname in ("MEMORY.md", "USER.md", "SOUL.md", "IDENTITY.md"):
            p = wb_dir / fname
            if p.exists():
                self._ingest_text(
                    p, export_root, "workbuddy", mb,
                    asset_type="profile", name=f"画像记忆 {fname}",
                    importance="high", relevance=0.85,
                )

        # 2) 项目级记忆
        mem_dir = wb_dir / "memory"
        if mem_dir.is_dir():
            self._ingest_dir(
                mem_dir, export_root, "workbuddy", mb,
                asset_type="memory", importance="medium", label="memory",
            )

        # 3) 可复用资产 skills/
        skills_dir = wb_dir / "skills"
        if skills_dir.is_dir():
            self._ingest_dir(
                skills_dir, export_root, "workbuddy", mb,
                asset_type="skill", importance="medium", label="skills",
            )

        # 4) 工作设置
        settings = wb_dir / "settings.json"
        if settings.exists():
            self._ingest_text(
                settings, export_root, "workbuddy", mb,
                asset_type="config", name="工作设置 settings.json",
                importance="medium", relevance=0.6, reauth_required=True,
            )

        # 5) 自动化（从 workbuddy.db 导出脱敏快照）
        db = wb_dir / "workbuddy.db"
        if db.exists():
            self._export_automations(db, export_root, mb)

        # 6) 项目索引（轻量，不复制会话数据）
        proj_dir = wb_dir / "projects"
        if proj_dir.is_dir():
            self._export_project_index(proj_dir, export_root, mb)

        # ---- 凭据抽取汇总 + handoff 治理 ----
        inv = self._dump_secrets(str(export_root))
        withheld = set(inv.get("by_category", {}).keys())
        if withheld:
            mb.set_policy(
                allowed=True,
                operation="export+extract-secrets",
                reason="检出的敏感凭据已抽取进加密保险库，原文仅留引用占位",
                withheld_data_classes=sorted(withheld),
                withheld_sources=["workbuddy"],
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
    def _resolve(self, account: str) -> Path:
        if account:
            p = Path(account).expanduser()
            if p.is_dir() and any((p / m).exists() for m in _WB_MARKERS):
                return p
            cand = p / ".workbuddy"
            if cand.is_dir():
                return cand
            if p.is_dir():
                return p
        return Path.home() / ".workbuddy"

    def _export_automations(
        self, db: Path, export_root: Path, mb: ManifestBuilder
    ) -> None:
        """从 workbuddy.db 读取 automations，导出为脱敏 JSON 快照。

        提示词里的凭据会被抽取进保险库（其余字段明文保留）。
        """
        dst = export_root / "workbuddy" / "automations.json"
        dst.parent.mkdir(parents=True, exist_ok=True)
        rows: List[Dict[str, Any]] = []
        try:
            conn = sqlite3.connect(str(db))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='automations'")
            if cur.fetchone() is None:
                conn.close()
                mb.add(self._mk_asset(
                    "workbuddy/automations.json", dst, "automation",
                    name="自动化 automations (空表)",
                    importance="high", relevance=0.8,
                    notes="automations 表不存在",
                ))
                return
            cur.execute("PRAGMA table_info(automations)")
            cols = {r["name"] for r in cur.fetchall()}
            want = ["id", "name", "prompt", "scheduleType", "rrule",
                    "status", "modelId", "validFrom", "validUntil"]
            pick = [c for c in want if c in cols]
            cur.execute(
                "SELECT {cols} FROM automations".format(cols=", ".join(pick))
            )
            for r in cur.fetchall():
                rec = {k: r[k] for k in pick}
                if rec.get("prompt"):
                    sanitized, records = extract_secrets(rec["prompt"])
                    rec["prompt"] = sanitized
                    for srec in records:
                        srec.source_hint = "workbuddy/automations.json"
                    self._secrets.extend(records)
                rows.append(rec)
            conn.close()
        except (sqlite3.Error, OSError) as e:
            dst.write_text(
                '{"error": "%s"}' % str(e).replace('"', "'"),
                encoding="utf-8",
            )
            mb.add(self._mk_asset(
                "workbuddy/automations.json", dst, "automation",
                name="自动化 automations (读取失败快照)",
                importance="high", relevance=0.8,
                notes=f"数据库读取异常: {e}",
            ))
            return

        dst.write_text(
            json.dumps(rows, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        mb.add(self._mk_asset(
            "workbuddy/automations.json", dst, "automation",
            name=f"自动化 automations ({len(rows)} 条)",
            importance="high", relevance=0.8,
            notes="已导出，提示词已脱敏（凭据已抽取进保险库）",
        ))

    def _export_project_index(
        self, proj_dir: Path, export_root: Path, mb: ManifestBuilder
    ) -> None:
        """仅导出项目目录的轻量索引（名称 + mtime），不复制庞大的会话数据。"""
        index: List[Dict[str, str]] = []
        for child in sorted(proj_dir.iterdir()):
            if child.is_dir():
                index.append({
                    "name": child.name,
                    "last_modified": _iso(child.stat().st_mtime),
                })
        dst = export_root / "workbuddy" / "project_index.json"
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(
            json.dumps(index, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        mb.add(self._mk_asset(
            "workbuddy/project_index.json", dst, "project_file",
            name=f"项目索引 ({len(index)} 个项目)",
            importance="low", relevance=0.4,
            notes="仅索引，未复制会话/文件数据，便于接收方定位项目",
        ))

    def _ingest_text(
        self, src: Path, export_root: Path, prefix: str, mb: ManifestBuilder,
        *, asset_type: str, name: str, importance: str, relevance: float,
        reauth_required: bool = False, sub: Optional[str] = None,
    ) -> None:
        rel_parts = [prefix]
        if sub is not None:
            rel_parts.append(sub)
        rel_parts.append(src.name)
        rel_str = "/".join(rel_parts)
        dst = export_root / rel_str
        dst.parent.mkdir(parents=True, exist_ok=True)

        size = src.stat().st_size
        if size > _MAX_REDACT_BYTES:
            shutil.copy2(src, dst)
            mb.add(self._mk_asset(
                rel_str, dst, asset_type, name, importance, relevance,
                reauth_required, notes="大文件(>50MB)原样拷贝，未做行内脱敏",
            ))
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
            rel_parts = [prefix, d.name, str(f.relative_to(d))]
            rel_str = "/".join(rel_parts)
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
        importance: str, relevance: float, reauth_required: bool = False,
        notes: Optional[str] = None,
    ) -> Asset:
        aid = "wb-" + hashlib.md5(rel_str.encode("utf-8")).hexdigest()[:12]
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
