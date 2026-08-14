"""ai-context-ferry 命令行入口。

子命令：
  list-platforms   列出已注册平台
  export           从指定平台导出 AI 上下文资产（写入 asset-manifest.json + 原始文件 + secrets.json）
  package          将导出目录打包为资产包（.ferry）：
                   - 普通资产以明文写入包内（无需口令即可阅读上下文）
                   - 抽取的敏感凭据单独加密进 secrets vault（口令 / 收件人模式）
                   - 打包时交互式询问要对哪些凭据类别加密（默认全部）
  handoff          解密资产包并渲染 SESSION.md 交接文档（无需口令即可读上下文；
                   提供口令/私钥可额外恢复 secrets）
  validate         校验 asset-manifest.json 是否符合 v2.0.0 schema
  keygen           生成收件人模式用的 X25519 密钥对
  init             生成本地配置模板 ferry.toml
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .adapters import REGISTRY, FIRST_WAVE, get_adapter
from .crypto import (
    encrypt_bytes, decrypt_bytes,
    encrypt_vault, decrypt_vault,
    generate_x25519_keypair, public_key_from_private,
)

_HERE = Path(__file__).resolve().parent
_SCHEMA_PATH = _HERE.parent.parent / "spec" / "asset-manifest.schema.json"
_TEMPLATE_PATH = _HERE.parent.parent / "templates" / "SESSION.md"

FERRY_BUNDLE_VERSION = "1.0"


# --------------------------------------------------------------------------- #
# 辅助
# --------------------------------------------------------------------------- #
def _err(msg: str) -> None:
    print(f"[error] {msg}", file=sys.stderr)


def _validate_manifest(manifest: dict) -> list[str]:
    try:
        import jsonschema
    except ImportError:
        return ["jsonschema 未安装，跳过校验"]
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    return [e.message for e in validator.iter_errors(manifest)]


def _read_passphrase(prompt: str) -> str:
    return getpass.getpass(prompt)


def _ask_secret_policy(categories: dict) -> str:
    """交互式询问要对哪些凭据类别加密。返回 'all' / 'none'。"""
    if not sys.stdin.isatty():
        return "all"
    summary = "、".join(f"{k}({v})" for k, v in sorted(categories.items()))
    print(f"[package] 检出敏感凭据类别：{summary}")
    ans = input("是否将这些凭据加密进保险库？[A]全部加密 / [N]不加密(仅留占位，最私密): ").strip().lower()
    if ans in ("n", "no", "不"):
        return "none"
    return "all"


# --------------------------------------------------------------------------- #
# 包构建 / 解包
# --------------------------------------------------------------------------- #
def build_bundle(export_dir: Path, policy: str, passphrase=None, recipient=None) -> dict:
    """把导出目录组装为明文资产包 dict（secrets 字段单独加密）。"""
    manifest = json.loads((export_dir / "asset-manifest.json").read_text(encoding="utf-8"))
    assets = manifest.get("assets", [])

    # 读取每个资产的明文内容
    bundle_assets = []
    for a in assets:
        rel = a.get("path")
        if not rel:
            continue
        p = export_dir / rel
        if p.exists():
            content = p.read_text(encoding="utf-8", errors="replace")
        else:
            content = ""
        bundle_assets.append({"rel_path": rel, "content": content})

    # 凭据保险库
    secrets_field = None
    secrets_json = export_dir / "secrets.json"
    if secrets_json.exists() and policy != "none":
        secrets = json.loads(secrets_json.read_text(encoding="utf-8"))
        if secrets:
            blob = encrypt_vault(secrets, passphrase=passphrase, recipient_pub_b64=recipient)
            secrets_field = blob.decode("utf-8")

    manifest.setdefault("secret_inventory", {})
    manifest["secret_inventory"]["encrypted"] = bool(secrets_field)

    return {
        "ferry_bundle": FERRY_BUNDLE_VERSION,
        "manifest": manifest,
        "assets": bundle_assets,
        "secrets": secrets_field,  # 已加密（ferry-crypt 信封 JSON）
    }


def extract_bundle_assets(bundle: dict, dst: Path) -> None:
    """把包内明文资产写回磁盘目录。"""
    dst.mkdir(parents=True, exist_ok=True)
    for a in bundle.get("assets", []):
        p = dst / a["rel_path"]
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(a.get("content", ""), encoding="utf-8")


def recover_secrets(bundle: dict, passphrase=None, identity=None) -> list:
    """若提供口令/私钥，解密保险库返回凭据列表；否则返回 []。"""
    field = bundle.get("secrets")
    if not field:
        return []
    blob = field.encode("utf-8") if isinstance(field, str) else field
    return decrypt_vault(blob, passphrase=passphrase, identity_priv_b64=identity)


# --------------------------------------------------------------------------- #
# 子命令
# --------------------------------------------------------------------------- #
def cmd_list_platforms(args) -> None:
    print("已注册平台：")
    for name in REGISTRY:
        tag = "（首批）" if name in FIRST_WAVE else ""
        print(f"  - {name}{tag}")
    print("\n首批（MVP 优先级）：", ", ".join(FIRST_WAVE))


def cmd_export(args) -> int:
    platform = args.platform
    if platform not in REGISTRY:
        _err(f"未注册平台: {platform}；可选: {list(REGISTRY)}")
        return 2
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        adapter = get_adapter(platform)
        manifest = adapter.export(account=args.account or "", out_dir=str(out_dir))
    except NotImplementedError as exc:
        _err(f"{platform} 适配器尚未实现：{exc}")
        return 3

    manifest_path = out_dir / "asset-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    assets = manifest.get("assets", [])
    inv = manifest.get("secret_inventory", {})
    print(f"[export] 平台={platform}")
    print(f"         导出目录={out_dir}")
    print(f"         资产数={len(assets)}")
    print(f"         检出凭据={inv.get('total', 0)} 条（将在 package 时加密）")
    print(f"         清单已写入 {manifest_path}")
    reauth = [a for a in assets if a.get("reauth_required")]
    if reauth:
        print(f"         需重新授权 {len(reauth)} 项：")
        for a in reauth:
            print(f"           - {a['name']}")
    return 0


def cmd_package(args) -> int:
    input_dir = Path(args.input)
    if not input_dir.is_dir():
        _err(f"导出目录不存在: {input_dir}")
        return 2
    manifest_path = input_dir / "asset-manifest.json"
    if not manifest_path.exists():
        _err("未找到 asset-manifest.json，请先运行 export")
        return 2

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors = _validate_manifest(manifest)
    if errors:
        _err("资产清单不符合 schema（仍会继续打包，但接收方可能解析失败）：")
        for e in errors:
            _err(f"  - {e}")

    secrets_json = input_dir / "secrets.json"
    if secrets_json.exists():
        try:
            cats = {}
            for r in json.loads(secrets_json.read_text(encoding="utf-8")):
                cats[r["category"]] = cats.get(r["category"], 0) + 1
        except (OSError, json.JSONDecodeError):
            cats = {}
    else:
        cats = {}

    # 决定加密策略
    policy = args.secrets_policy
    if policy == "prompt":
        policy = _ask_secret_policy(cats)
    if policy not in ("all", "none"):
        policy = "all"

    passphrase = args.passphrase
    recipient = args.recipient
    if cats and policy == "all" and not passphrase and not recipient:
        passphrase = _read_passphrase("请输入用于加密凭据保险库的口令：")

    try:
        bundle = build_bundle(
            input_dir, policy, passphrase=passphrase, recipient=recipient
        )
    except ValueError as exc:
        _err(str(exc))
        return 2

    out_path = Path(args.output)
    if out_path.suffix != ".ferry":
        out_path = out_path.with_suffix(".ferry")
    out_path.write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")

    mode = "收件人模式" if recipient else ("口令模式" if passphrase else "未加密")
    enc_count = sum(cats.values()) if (policy == "all" and (passphrase or recipient)) else 0
    print(f"[package] 凭据策略={policy}（{mode}）")
    print(f"          资产明文写入包内（无需口令可读上下文）")
    print(f"          已加密凭据={enc_count} 条")
    print(f"          已写入 {out_path}")

    # 安全清理本地明文 secrets.json（除非 --keep-secrets）
    if secrets_json.exists() and not args.keep_secrets:
        try:
            data = bytearray(secrets_json.read_bytes())
            for i in range(len(data)):
                data[i] = 0
            secrets_json.write_bytes(bytes(data))
            secrets_json.unlink()
        except OSError:
            pass
    return 0


def cmd_handoff(args) -> int:
    bundle_path = Path(args.bundle)
    if not bundle_path.exists():
        _err(f"资产包不存在: {bundle_path}")
        return 2

    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    if bundle.get("ferry_bundle") != FERRY_BUNDLE_VERSION:
        _err("资产包格式版本不匹配，可能由更新版本生成")
        return 2

    extract_dir = Path(args.extract) if args.extract else (bundle_path.parent / bundle_path.stem)
    extract_bundle_assets(bundle, extract_dir)

    manifest = bundle.get("manifest", {})
    # 同时把结构化 manifest 落盘（接收方既可读 SESSION.md，也有机器可解析的清单）
    (extract_dir / "asset-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # 若提供口令/私钥，额外恢复凭据到独立文件（不回写进 SESSION.md，避免明文泄露）
    recovered = []
    if args.passphrase or args.identity:
        try:
            recovered = recover_secrets(
                bundle, passphrase=args.passphrase, identity=args.identity
            )
            if recovered:
                (extract_dir / "secrets.recovered.json").write_text(
                    json.dumps(recovered, ensure_ascii=False, indent=2), encoding="utf-8"
                )
        except Exception as exc:  # 口令错误等
            _err(f"凭据恢复失败（口令/私钥不正确或包损坏）：{exc}")

    session_md = _render_session(manifest, len(recovered))
    out_md = Path(args.output)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(session_md, encoding="utf-8")

    print(f"[handoff] 已解包到 {extract_dir}")
    print(f"          交接文档已写入 {out_md}")
    if recovered:
        print(f"          凭据已恢复 {len(recovered)} 条 → {extract_dir / 'secrets.recovered.json'}")
    return 0


def _render_session(manifest: dict, recovered_count: int = 0) -> str:
    try:
        from jinja2 import Template
    except ImportError:
        _err("jinja2 未安装，无法渲染 SESSION.md")
        raise

    raw = _TEMPLATE_PATH.read_text(encoding="utf-8")
    assets = manifest.get("assets", [])
    source = manifest.get("source", {})
    handoff = manifest.get("handoff", {})
    inv = manifest.get("secret_inventory", {})
    high = [a for a in assets if a.get("importance") == "high"]
    reauth = [a for a in assets if a.get("reauth_required")]

    if handoff.get("suggested_next_action"):
        next_steps = handoff["suggested_next_action"]
    elif reauth:
        next_steps = (
            "在新账号导入后，请对以下需重新授权的资产手动重新鉴权：\n"
            + "\n".join(f"- {a['name']}" for a in reauth)
        )
    else:
        next_steps = "（无明确下一步；按资产清单继续即可）"

    blockers = handoff.get("blockers", [])
    blockers_text = "\n".join(f"- {b.get('summary')}" for b in blockers) or "无"

    secret_line = (
        f"共检出 {inv.get('total', 0)} 条敏感凭据；"
        f"{'已加密（接收方凭口令/私钥可恢复）' if inv.get('encrypted') else '未加密（仅留占位）'}。"
    )
    if recovered_count:
        secret_line += f" 本次已恢复 {recovered_count} 条到 secrets.recovered.json。"

    ctx = {
        "generated_at": manifest.get("generated_at"),
        "source": source,
        "project_background": (
            f"本包来自平台 {source.get('platform')}（账号已脱敏："
            f"{source.get('account_id')}），共导出 {len(assets)} 项上下文资产。"
        ),
        "key_decisions": (
            "\n".join(f"- {a['name']}（{a['asset_type']}）" for a in high)
            or "（无高重要度资产）"
        ),
        "in_progress": "（由接收方按资产清单继续）",
        "blockers": blockers_text,
        "next_steps": next_steps,
        "assets": assets,
        "secret_summary": secret_line,
        "verification_summary": (
            f"共 {len(assets)} 项资产；{len(reauth)} 项需重新授权；"
            "各资产 SHA256 见清单 checksum 字段。"
        ),
    }
    return Template(raw).render(**ctx)


def cmd_validate(args) -> int:
    p = Path(args.manifest)
    if not p.exists():
        _err(f"文件不存在: {p}")
        return 2
    manifest = json.loads(p.read_text(encoding="utf-8"))
    errors = _validate_manifest(manifest)
    if errors:
        _err(f"校验未通过，共 {len(errors)} 处：")
        for e in errors:
            _err(f"  - {e}")
        return 1
    print(f"[validate] OK：{p} 符合 asset-manifest.schema.json v2.0.0")
    return 0


def cmd_keygen(args) -> int:
    pub, priv = generate_x25519_keypair()
    print("# 收件人模式 X25519 密钥对（请妥善保管私钥，公钥可分享给导出方）")
    print(f"public_key:  {pub}")
    print(f"private_key: {priv}")
    if args.save:
        Path(args.save).write_text(
            json.dumps({"public_key": pub, "private_key": priv}, indent=2),
            encoding="utf-8",
        )
        print(f"已保存到 {args.save}")
    return 0


def cmd_init(args) -> int:
    cfg = Path(args.output)
    if cfg.exists() and not args.force:
        _err(f"{cfg} 已存在，使用 --force 覆盖")
        return 2
    template = (
        "# ai-context-ferry 配置模板\n"
        "# 说明：passphrase 不应写入文件；此处仅记录收件人公钥以便复用。\n"
        "platforms = [\"claude_code\", \"codex\", \"chatgpt\", \"cursor\", \"workbuddy\"]\n"
        "# recipient_public_key = \"<X25519 public key base64，由 `ai-context-ferry keygen` 生成共享>\"\n"
    )
    cfg.write_text(template, encoding="utf-8")
    print(f"[init] 已生成配置模板 {cfg}")
    return 0


# --------------------------------------------------------------------------- #
# 解析器
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ai-context-ferry",
        description="开源跨平台 AI 上下文迁移与交接工具（人↔人 / Agent↔Agent）",
    )
    p.add_argument("--version", action="version", version="ai-context-ferry 0.1.0")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list-platforms", help="列出已注册平台").set_defaults(
        func=cmd_list_platforms
    )

    e = sub.add_parser("export", help="从平台导出资产")
    e.add_argument("--platform", required=True, help="claude_code/codex/chatgpt/cursor/workbuddy")
    e.add_argument("--account", default="", help="源账号/主目录（留空=当前用户）")
    e.add_argument("--out", required=True, help="导出目录")
    e.set_defaults(func=cmd_export)

    pk = sub.add_parser("package", help="打包为资产包 .ferry（凭据单独加密）")
    pk.add_argument("--input", required=True, help="export 输出的目录")
    pk.add_argument("--output", required=True, help=".ferry 输出路径")
    pk.add_argument("--passphrase", default=None, help="加密口令（留空则交互输入）")
    pk.add_argument("--recipient", default=None, help="收件人 X25519 公钥(base64)")
    pk.add_argument("--secrets-policy", default="prompt",
                    choices=["prompt", "all", "none"],
                    help="凭据加密策略：prompt=交互询问(默认) / all=全加密 / none=不加密")
    pk.add_argument("--keep-secrets", action="store_true",
                    help="打包后保留本地明文 secrets.json（默认会安全删除）")
    pk.set_defaults(func=cmd_package)

    h = sub.add_parser("handoff", help="解密资产包并生成 SESSION.md")
    h.add_argument("--bundle", required=True, help=".ferry 资产包路径")
    h.add_argument("--output", required=True, help="SESSION.md 输出路径")
    h.add_argument("--extract", default=None, help="解包目录（默认=包同目录/包名）")
    h.add_argument("--passphrase", default=None, help="解密口令（提供可恢复凭据）")
    h.add_argument("--identity", default=None, help="收件人私钥(base64)用于收件人模式")
    h.set_defaults(func=cmd_handoff)

    v = sub.add_parser("validate", help="校验 asset-manifest.json")
    v.add_argument("--manifest", required=True, help="manifest 路径")
    v.set_defaults(func=cmd_validate)

    k = sub.add_parser("keygen", help="生成 X25519 密钥对")
    k.add_argument("--save", default=None, help="将密钥对保存到 JSON 文件")
    k.set_defaults(func=cmd_keygen)

    i = sub.add_parser("init", help="生成配置模板 ferry.toml")
    i.add_argument("--output", default="ferry.toml", help="输出路径")
    i.add_argument("--force", action="store_true", help="覆盖已存在文件")
    i.set_defaults(func=cmd_init)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
