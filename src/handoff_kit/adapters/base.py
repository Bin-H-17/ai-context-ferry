"""平台适配器抽象接口 + 资产清单构造器。

每个来源平台实现一个 Adapter，负责把该平台的资产导出为
`asset-manifest` 草稿（参见 spec/asset-manifest.schema.json）。
导出的原始文件落在 out_dir 下，清单里用相对路径引用。

本模块同时提供：
- ``Asset``：单个资产的强类型描述。
- ``ManifestBuilder``：把若干 Asset 组装成符合 v2.0.0 schema 的清单，
  并可在打包阶段写入 handoff（交接）语义与脱敏治理摘要。
- 工具函数：``sha256_of``（完整性校验）、``privacy_mask``（账号脱敏）。
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..redact import SecretRecord

# 与 spec/asset-manifest.schema.json 的 asset_type enum 保持一致
ASSET_TYPES = (
    "memory",
    "profile",
    "project_file",
    "conversation",
    "skill",
    "automation",
    "config",
    "integration",
)

# schema 文件相对本文件的路径：base.py -> adapters -> handoff_kit -> src -> ai-context-ferry
_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "spec" / "asset-manifest.schema.json"
)


def sha256_of(path: str) -> str:
    """计算文件 sha256（用于 manifest.assets[].checksum）。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def privacy_mask(value: str) -> str:
    """对账号标识做不可逆脱敏，仅保留 16 位哈希前缀，兼顾安全与可辨识性。

    导出包可能被分享/提交，原始邮箱/路径不应明文出现在清单里。
    """
    return "mask:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


@dataclass
class Asset:
    """单个资产的强类型描述。字段对应 schema 的 assets[] 项。"""

    asset_id: str
    asset_type: str  # 必须是 ASSET_TYPES 之一
    name: str
    importance: str  # high / medium / low
    transferable: bool
    path: Optional[str] = None
    size_bytes: Optional[int] = None
    last_modified: Optional[str] = None
    relevance: float = 0.5  # 0~1
    reauth_required: bool = False
    depends_on: Optional[List[str]] = None
    checksum: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "name": self.name,
            "importance": self.importance,
            "transferable": self.transferable,
        }
        if self.path is not None:
            d["path"] = self.path
        if self.size_bytes is not None:
            d["size_bytes"] = self.size_bytes
        if self.last_modified is not None:
            d["last_modified"] = self.last_modified
        d["relevance"] = self.relevance
        if self.reauth_required:
            d["reauth_required"] = True
        if self.depends_on:
            d["depends_on"] = self.depends_on
        if self.checksum is not None:
            d["checksum"] = self.checksum
        if self.notes is not None:
            d["notes"] = self.notes
        return d


class ManifestBuilder:
    """组装符合 asset-manifest.schema.json v2.0.0 的清单。"""

    def __init__(
        self,
        platform: str,
        account_id: str,
        exported_by: str = "ai-context-ferry",
    ) -> None:
        self._platform = platform
        self._account_id = account_id  # 调用方应自行脱敏
        self._exported_by = exported_by
        self._assets: List[Asset] = []
        self._migration_goal: Optional[str] = None
        self._repo_context: Optional[Dict[str, Optional[str]]] = None
        self._handoff: Dict[str, Any] = {}

    # ---- 资产收集 ----
    def add(self, asset: Asset) -> "ManifestBuilder":
        if asset.asset_type not in ASSET_TYPES:
            raise ValueError(
                f"非法 asset_type: {asset.asset_type}；可选: {ASSET_TYPES}"
            )
        self._assets.append(asset)
        return self

    # ---- 顶层可选字段 ----
    def set_migration_goal(self, goal: str) -> "ManifestBuilder":
        self._migration_goal = goal
        return self

    def set_repo_context(
        self,
        repository: Optional[str] = None,
        branch: Optional[str] = None,
        latest_commit: Optional[str] = None,
    ) -> "ManifestBuilder":
        self._repo_context = {
            "repository": repository,
            "branch": branch,
            "latest_commit": latest_commit,
        }
        return self

    # ---- handoff（交接）语义便捷方法 ----
    def withheld(self, category: str, policy_reason: str, safe_summary: str) -> "ManifestBuilder":
        """登记一处被脱敏 withholding 的上下文类别。"""
        items = self._handoff.setdefault("withheld_context_summary", [])
        items.append(
            {
                "category": category,
                "policy_reason": policy_reason,
                "safe_summary": safe_summary,
            }
        )
        return self

    def set_policy(
        self,
        allowed: bool,
        operation: str,
        reason: str,
        withheld_data_classes: Optional[List[str]] = None,
        withheld_sources: Optional[List[str]] = None,
    ) -> "ManifestBuilder":
        self._handoff["policy_summary"] = {
            "allowed": allowed,
            "operation": operation,
            "reason": reason,
            "withheld_data_classes": withheld_data_classes or [],
            "withheld_sources": withheld_sources or [],
        }
        return self

    def set_blocker(self, summary: str, confidence: float = 0.5) -> "ManifestBuilder":
        blockers = self._handoff.setdefault("blockers", [])
        blockers.append({"summary": summary, "confidence": confidence})
        return self

    def set_next_action(self, text: str) -> "ManifestBuilder":
        self._handoff["suggested_next_action"] = text
        return self

    def set_confidence(self, value: float) -> "ManifestBuilder":
        self._handoff["confidence"] = max(0.0, min(1.0, value))
        return self

    def set_handoff_raw(self, handoff: Dict[str, Any]) -> "ManifestBuilder":
        self._handoff.update(handoff)
        return self

    # ---- 产出 ----
    def build(self) -> Dict[str, Any]:
        source: Dict[str, Any] = {
            "platform": self._platform,
            "account_id": self._account_id,
            "exported_by": self._exported_by,
        }
        if self._repo_context is not None:
            source["repo_context"] = self._repo_context

        manifest: Dict[str, Any] = {
            "schema_version": "2.0.0",
            "generated_at": _now_iso(),
            "source": source,
            "assets": [a.to_dict() for a in self._assets],
        }
        if self._migration_goal is not None:
            manifest["migration_goal"] = self._migration_goal
        if self._handoff:
            manifest["handoff"] = self._handoff
        return manifest

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.build(), ensure_ascii=False, indent=indent)

    def validate(self) -> List[str]:
        """用 jsonschema 校验 build() 结果，返回错误列表（空 = 通过）。"""
        try:
            import jsonschema  # 延迟导入，避免无依赖环境报错
        except ImportError:
            return ["jsonschema 未安装，跳过 schema 校验"]
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = jsonschema.Draft7Validator(schema)
        errors = sorted(validator.iter_errors(self.build()), key=lambda e: e.path)
        return [f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors]


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class BaseAdapter(ABC):
    #: 平台标识，需与 CLI --platform 及 REGISTRY 键一致
    platform: str = "base"

    def __init__(self) -> None:
        # 抽取出的敏感凭据（在 export 阶段累积，package 阶段加密进保险库）
        self._secrets: List[SecretRecord] = []

    # ---- 凭据抽取辅助 ----
    def _redact_collect_text(
        self,
        rel_path: str,
        src_path: str,
        dst_dir: str,
        asset_type: str,
        name: str,
        importance: str,
        relevance: float,
        reauth_required: bool = False,
        notes: Optional[str] = None,
    ) -> "Asset":
        """读取源文件 → 抽取敏感凭据 → 写脱敏副本到 dst_dir/rel_path → 登记 Asset。

        被抽出的凭据会累积到 ``self._secrets``，由 ``_dump_secrets`` 在导出末尾落盘。
        """
        from .. import redact as R

        sanitized, records, _cats = R.extract_secrets_file(src_path)
        for r in records:
            r.source_hint = rel_path
        self._secrets.extend(records)

        dst = Path(dst_dir) / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(sanitized, encoding="utf-8")
        return self._mk_asset(
            rel_path, dst, asset_type, name, importance, relevance,
            reauth_required, notes,
        )

    def _dump_secrets(self, out_dir: str) -> Dict[str, Any]:
        """把累积的凭据写入 secrets.json（明文，待 package 加密），返回 secret_inventory。"""
        from .. import redact as R

        out = Path(out_dir)
        secrets_path = out / "secrets.json"
        if self._secrets:
            secrets_path.write_text(
                json.dumps(
                    [vars(r) for r in self._secrets], ensure_ascii=False, indent=2
                ),
                encoding="utf-8",
            )
            inv = R.build_secret_inventory(self._secrets, encrypted=False)
        else:
            inv = {"total": 0, "encrypted": False, "by_category": {}, "examples": []}
            if secrets_path.exists():
                secrets_path.unlink()
        return inv

    @abstractmethod
    def export(self, account: str, out_dir: str) -> Dict[str, Any]:
        """导出该平台资产。

        Args:
            account: 源账号标识（具体含义由各平台决定，如邮箱/local path/session）。
            out_dir: 导出物存放目录（绝对路径）。

        Returns:
            asset-manifest 草稿 dict，至少包含 assets 字段，
            schema_version / generated_at / source 由 package 阶段补全。
        """
        raise NotImplementedError
