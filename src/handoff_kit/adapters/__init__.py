from .base import BaseAdapter
from .codex import CodexAdapter
from .claude_code import ClaudeCodeAdapter
from .chatgpt import ChatgptAdapter
from .cursor import CursorAdapter
from .workbuddy import WorkbuddyAdapter
from .hermes import HermesAdapterTemplate

REGISTRY = {
    "codex": CodexAdapter,
    "claude_code": ClaudeCodeAdapter,
    "chatgpt": ChatgptAdapter,
    "cursor": CursorAdapter,
    "workbuddy": WorkbuddyAdapter,
}

# 首批平台（MVP 优先级），用于 CLI / 文档展示
FIRST_WAVE = ["claude_code", "codex", "chatgpt", "cursor", "workbuddy"]


def get_adapter(platform: str) -> BaseAdapter:
    cls = REGISTRY.get(platform)
    if cls is None:
        raise KeyError(f"未注册平台: {platform}；可选: {list(REGISTRY)}")
    return cls()
