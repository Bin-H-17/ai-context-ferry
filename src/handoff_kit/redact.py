"""敏感信息识别、抽取与脱敏（redaction / secret extraction）。

设计目标（产品负责人授权）：
- 资产包要在账号 / 人之间流转，"导出即泄露风险"是头等大事。
- 但"转移"的核心是**接收方要能拿回凭据**，所以这里不走"就地抹掉"的极端，
  而是走「**分级**」策略：
    * 普通内容（对话、记忆、markdown、代码）→ 明文保留，不加密（平平无奇无需加密）。
    * 识别出的敏感凭据 → 从原文**抽取**出来，单独放进加密保险库（secrets vault），
      原文只留一个引用占位 «SECRET:{category}:{sid}»，既不泄露值、又能让接收方
      在拿到口令/私钥后恢复。
- 在 `package` 阶段由工具**交互式询问**用户：哪些类别要加密（默认全部加密）。

设计参考：
- GitHub 推送保护（push protection）对密钥字面量的识别思路。
- 各类 secret scanning 工具（gitleaks / trufflehog）的常见模式集合。
  本模块只做正则层面的浅层识别，不解析语义；够用且零依赖。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# 脱敏占位符（向后兼容：旧 redact_text 仍就地遮罩用这个）
PLACEHOLDER = "«REDACTED:{category}»"

# 抽取后留在原文的引用占位：指明"这里曾有一个某类别的凭据"，但不暴露值。
SECRET_REF = "«SECRET:{category}:{sid}»"


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #
@dataclass
class SecretRecord:
    """一条被抽取的敏感凭据。"""

    sid: str
    category: str
    value: str
    preview: str  # 遮罩后的预览，如 sk-••••wXYZ
    source_hint: str = ""  # 来源文件/位置提示（由调用方填写）


@dataclass
class SecretFinding:
    category: str
    value: str
    start: int
    end: int


# (类别, 编译正则)。private_key 放最前，优先占据最长跨度，避免被小模式切碎。
_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            r"[\s\S]+?"
            r"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
    ),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\b")),
    ("bearer_token", re.compile(r"\b[Bb]earer\s+[A-Za-z0-9._~+/-]+=*\b")),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b([api[_-]?key|apikey|secret|token|access[_-]?token|"
            r"refresh[_-]?token|password|passwd|pwd|client[_-]?secret)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{8,})['\"]?"
        ),
    ),
    (
        "url_credential",
        re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s:@]+@"),
    ),
]


# --------------------------------------------------------------------------- #
# 底层：扫描 + 抽取
# --------------------------------------------------------------------------- #
def _mask_preview(value: str, keep: int = 4) -> str:
    """生成遮罩预览：保留首尾各 keep 个字符，中间用 • 代替。"""
    if len(value) <= keep * 2 + 1:
        return "•" * min(len(value), 8)
    return f"{value[:keep]}••••{value[-keep:]}"


def scan_secrets(text: str) -> List[SecretFinding]:
    """扫描文本，返回所有敏感凭据命中（含类别、值、起止位置）。"""
    findings: List[SecretFinding] = []
    claimed: List[Tuple[int, int]] = []  # 已被更长模式（如 private_key）占据的区间

    def _overlaps(s: int, e: int) -> bool:
        return any(not (e <= cs or s >= ce) for cs, ce in claimed)

    for category, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            s, e = m.start(), m.end()
            if _overlaps(s, e):
                continue
            # 取值规则：赋值型/URL 型取"值"部分，其余取整段匹配。
            if category == "credential_assignment":
                value = m.group(2)
            elif category == "url_credential":
                value = m.group(0).split("://", 1)[1].rsplit("@", 1)[0]
            else:
                value = m.group(0)
            if not value:
                continue
            findings.append(SecretFinding(category=category, value=value, start=s, end=e))
            claimed.append((s, e))
    return findings


def extract_secrets(text: str) -> Tuple[str, List[SecretRecord]]:
    """把敏感凭据从文本中抽取出来，原文替换为引用占位。

    返回 (脱敏后文本, 凭据记录列表)。同一类别多次出现会用 sid 区分。
    """
    findings = scan_secrets(text)
    if not findings:
        return text, []

    # 从后往前替换，避免位置偏移
    spans = sorted(findings, key=lambda f: f.start, reverse=True)
    out = text
    records: List[SecretRecord] = []
    seen: Dict[str, int] = {}
    for f in spans:
        cat = f.category
        seen[cat] = seen.get(cat, 0) + 1
        sid = f"{cat[:3]}{seen[cat]}"
        rec = SecretRecord(
            sid=sid,
            category=cat,
            value=f.value,
            preview=_mask_preview(f.value),
        )
        records.append(rec)
        ref = SECRET_REF.format(category=cat, sid=sid)
        if cat == "credential_assignment":
            # 保留键名，只遮值：key = «SECRET:...»
            # 用原始匹配的前半（键名部分）替换为 "键名 = ref"
            m = _PATTERNS_dict()[cat].search(text, f.start)
            key_name = m.group(1) if m else "credential"
            replacement = f"{key_name} = {ref}"
        elif cat == "url_credential":
            replacement = f"{text[f.start:f.start + text[f.start:].find('://') + 3]}{ref}@"
        else:
            replacement = ref
        out = out[: f.start] + replacement + out[f.end :]

    records.reverse()  # 还原为正向顺序
    return out, records


def _PATTERNS_dict() -> Dict[str, "re.Pattern[str]"]:
    return {cat: pat for cat, pat in _PATTERNS}


def extract_secrets_file(
    path: str, encoding: str = "utf-8"
) -> Tuple[str, List[SecretRecord], Set[str]]:
    """读取文件并抽取凭据。读取失败返回 ("", [], {"file_error"})。"""
    try:
        with open(path, "r", encoding=encoding, errors="replace") as f:
            text = f.read()
    except OSError:
        return "", [], {"file_error"}
    sanitized, records = extract_secrets(text)
    cats = {r.category for r in records}
    return sanitized, records, cats


def build_secret_inventory(records: List[SecretRecord], encrypted: bool) -> Dict:
    """汇总凭据清单，写入 manifest.secret_inventory。"""
    by_cat: Dict[str, int] = {}
    examples: List[str] = []
    for r in records:
        by_cat[r.category] = by_cat.get(r.category, 0) + 1
        if len(examples) < 8:
            examples.append(f"{r.category}:{r.preview} (from {r.source_hint or '?'})")
    return {
        "total": len(records),
        "encrypted": encrypted,
        "by_category": by_cat,
        "examples": examples,
    }


# --------------------------------------------------------------------------- #
# 向后兼容：就地遮罩（旧接口，测试与兜底仍可用）
# --------------------------------------------------------------------------- #
def redact_text(text: str) -> Tuple[str, Set[str]]:
    """就地遮罩（保守优先：宁多遮勿漏遮）。返回 (文本, 类别集合)。"""
    if not text:
        return text, set()
    categories: Set[str] = set()

    def _sub(category: str, match: "re.Match[str]") -> str:
        categories.add(category)
        if category == "credential_assignment":
            return f"{match.group(1)} = {PLACEHOLDER.format(category='credential')}"
        if category == "url_credential":
            return f"{match.group(1)}{PLACEHOLDER.format(category='credential')}@"
        return PLACEHOLDER.format(category=category)

    out = text
    for category, pattern in _PATTERNS:
        out = pattern.sub(lambda m, c=category: _sub(c, m), out)
    return out, categories


def redact_file(path: str, encoding: str = "utf-8") -> Tuple[str, Set[str]]:
    """读取文件并就地遮罩。"""
    try:
        with open(path, "r", encoding=encoding, errors="replace") as f:
            text = f.read()
    except OSError:
        return "", {"file_error"}
    return redact_text(text)


def summarize(categories: Set[str]) -> str:
    """把被遮类别整理成一句话摘要。"""
    if not categories:
        return "无（未检出已知敏感信息）"
    return "已脱敏并 withholding 以下类别：" + "、".join(sorted(categories))
