"""自定义适配器模板（示例）。

本项目不绑定任何单一"Hermes"平台——设计目标是**主流 AI Agent 都能适配**：
Claude Code / Codex / ChatGPT / Cursor / WorkBuddy 均已内置（见同目录各适配器）。
若你要接入新的 Agent 平台，复制本文件改造成新适配器即可，三步：

1. 继承 ``BaseAdapter``，设置 ``platform`` 为该平台标识（CLI --platform 用它）。
2. 实现 ``export(account, out_dir)``：
   - 用 ``self._redact_collect_text(rel_path, src_path, dst_dir, ...)`` 读取并
     **抽取敏感凭据**、写脱敏副本、登记 Asset；
   - 对已知文本（如解析后的 JSON）用 ``self._redact_collect_text_inline(...)``；
   - 末尾调用 ``inv = self._dump_secrets(out_dir)`` 落盘 secrets.json，
     并把 ``manifest["secret_inventory"] = inv`` 写回清单。
3. 在 ``adapters/__init__.py`` 的 ``REGISTRY`` 里注册。

下面是一个最小骨架（默认未注册到 REGISTRY，避免暴露未完成适配器）。
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from .base import Asset, ManifestBuilder, privacy_mask, sha256_of


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class HermesAdapterTemplate:
    """新平台适配器骨架——复制改名后即可接入。"""

    platform = "my_agent"

    def export(self, account: str = "", out_dir: str = "") -> Dict[str, Any]:
        root = Path(account).expanduser() if account else Path.home() / ".my_agent"
        export_root = Path(out_dir)
        (export_root / self.platform).mkdir(parents=True, exist_ok=True)

        mb = ManifestBuilder(self.platform, privacy_mask(str(root)))

        # 示例：抽取某个配置文件（按需替换为你的平台真实布局）
        cfg = root / "config.json"
        if cfg.exists():
            mb.add(self._redact_collect_text(
                f"{self.platform}/config.json", str(cfg), str(export_root),
                "config", "配置 config.json", "medium", 0.6, reauth_required=True,
            ))

        # 重要：抽取凭据并写回 secret_inventory
        inv = self._dump_secrets(str(export_root))
        mb.set_confidence(0.5 if mb._assets else 0.2)
        manifest = mb.build()
        manifest["secret_inventory"] = inv
        return manifest

    def _mk_asset(self, rel_str: str, dst: Path, asset_type: str, name: str,
                  importance: str, relevance: float, reauth_required: bool = False,
                  notes: Optional[str] = None) -> Asset:
        aid = "ma-" + hashlib.md5(rel_str.encode("utf-8")).hexdigest()[:12]
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
