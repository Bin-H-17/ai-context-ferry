"""ai-context-ferry 测试套件。

覆盖：
- crypto 加解密（口令 / 收件人双模式 + 错误口令失败）
- redact 脱敏（多类别）
- ManifestBuilder schema 校验
- Claude Code / Codex 适配器（合成 fixture + 脱敏验证）
- 端到端：export → package → handoff 闭环
"""

import json
from pathlib import Path

import pytest

from handoff_kit.crypto import decrypt_bytes, encrypt_bytes, generate_x25519_keypair
from handoff_kit.redact import redact_text
from handoff_kit.adapters.base import ASSET_TYPES, Asset, ManifestBuilder
from handoff_kit.adapters import get_adapter
from handoff_kit.cli import main as cli_main


# --------------------------------------------------------------------------- #
# crypto
# --------------------------------------------------------------------------- #
def test_crypto_passphrase_roundtrip():
    data = b"hello ferry context"
    blob = encrypt_bytes(data, passphrase="s3cret")
    assert decrypt_bytes(blob, passphrase="s3cret") == data
    with pytest.raises(Exception):
        decrypt_bytes(blob, passphrase="wrong")


def test_crypto_recipient_roundtrip():
    pub, priv = generate_x25519_keypair()
    blob = encrypt_bytes(b"handoff to another account", recipient_pub_b64=pub)
    assert decrypt_bytes(blob, identity_priv_b64=priv) == b"handoff to another account"
    # 用错的私钥应失败
    _, priv2 = generate_x25519_keypair()
    with pytest.raises(Exception):
        decrypt_bytes(blob, identity_priv_b64=priv2)


# --------------------------------------------------------------------------- #
# redact
# --------------------------------------------------------------------------- #
def test_redact_masks_secrets():
    text = (
        'aws = AKIA1234567890ABCDEF\n'
        'api_key = "sk-abcdefghijklmnopqrstuvwxyz"\n'
        'token: "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
        'normal_line = "keep me"\n'
    )
    redacted, cats = redact_text(text)
    assert "AKIA1234567890ABCDEF" not in redacted
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in redacted
    assert "keep me" in redacted
    assert "aws_key" in cats
    assert "api_key" in redacted  # 键名保留，仅遮值


def test_redact_private_key_block():
    block = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBfooobarbaz...\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    redacted, cats = redact_text(block)
    assert "MIIBfooobarbaz" not in redacted
    assert "private_key" in cats


# --------------------------------------------------------------------------- #
# manifest
# --------------------------------------------------------------------------- #
def test_manifest_builder_validates():
    mb = ManifestBuilder("codex", "mask:abc123")
    mb.add(Asset(
        asset_id="cx-1", asset_type="memory", name="AGENTS.md",
        importance="high", transferable=True, relevance=0.9,
        path="codex/AGENTS.md", checksum="deadbeef",
    ))
    mb.withheld("api_key", "导出脱敏", "已替换")
    manifest = mb.build()
    assert manifest["schema_version"] == "2.0.0"
    assert manifest["source"]["platform"] == "codex"
    assert mb.validate() == []


def test_manifest_rejects_bad_asset_type():
    mb = ManifestBuilder("codex", "mask:x")
    with pytest.raises(ValueError):
        mb.add(Asset(asset_id="a", asset_type="bogus", name="n",
                     importance="low", transferable=True))


# --------------------------------------------------------------------------- #
# 合成 fixture 构造
# --------------------------------------------------------------------------- #
def _make_claude_home(home: Path):
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "CLAUDE.md").write_text(
        "我是全局记忆。\n密码 password = supersecret123456\n", encoding="utf-8"
    )
    (claude / "settings.json").write_text('{"model":"opus"}', encoding="utf-8")
    proj = claude / "projects" / "-foo-bar"
    proj.mkdir(parents=True)
    (proj / "sess-001.jsonl").write_text(
        '{"type":"user","text":"帮我修 bug，token=abcdefghijklmnop"}\n',
        encoding="utf-8",
    )
    (claude / "history.jsonl").write_text('{"cmd":"ls"}\n', encoding="utf-8")


def _make_codex_home(home: Path):
    codex = home / ".codex"
    codex.mkdir(parents=True)
    (codex / "AGENTS.md").write_text("Codex 全局记忆。\n", encoding="utf-8")
    (codex / "config.toml").write_text('model = "gpt-5"\n', encoding="utf-8")
    (codex / "auth.json").write_text(
        json.dumps({"access_token": "ghp_" + "a" * 36,
                    "refresh_token": "refreshsecretvalue12345678"}),
        encoding="utf-8",
    )
    sess = codex / "sessions" / "2026" / "01" / "01"
    sess.mkdir(parents=True)
    (sess / "rollout-abc.jsonl").write_text(
        '{"type":"session_meta","session_id":"abc","source":"cli","cwd":"/foo"}\n'
        '{"type":"response_item","text":"hi"}\n',
        encoding="utf-8",
    )


# --------------------------------------------------------------------------- #
# 适配器
# --------------------------------------------------------------------------- #
def test_claude_adapter(tmp_path):
    home = tmp_path / "home"
    _make_claude_home(home)
    out = tmp_path / "export"
    adapter = get_adapter("claude_code")
    manifest = adapter.export(account=str(home), out_dir=str(out))

    assert manifest["source"]["platform"] == "claude_code"
    types = {a["asset_type"] for a in manifest["assets"]}
    assert "memory" in types and "conversation" in types

    # 脱敏生效：导出文件里不出现原口令
    claude_md = out / "claude_code" / "CLAUDE.md"
    assert claude_md.exists()
    assert "supersecret123456" not in claude_md.read_text(encoding="utf-8")

    # manifest 符合 schema
    mb = ManifestBuilder("claude_code", "x")
    # 用独立校验：直接对 adapter 产出的 manifest 校验
    from handoff_kit.adapters.base import _SCHEMA_PATH
    import jsonschema
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    errs = list(jsonschema.Draft7Validator(schema).iter_errors(manifest))
    assert not errs, [e.message for e in errs]


def test_codex_adapter(tmp_path):
    home = tmp_path / "home"
    _make_codex_home(home)
    out = tmp_path / "export"
    adapter = get_adapter("codex")
    manifest = adapter.export(account=str(home), out_dir=str(out))

    assert manifest["source"]["platform"] == "codex"
    # auth.json 被标记需重授权
    auth_asset = next(a for a in manifest["assets"] if a["name"].endswith("auth.json"))
    assert auth_asset["reauth_required"] is True
    auth_text = (out / auth_asset["path"]).read_text(encoding="utf-8")
    assert "ghp_" + "a" * 36 not in auth_text

    # session_meta 被识别（会话资产名包含 cli/）
    conv = next(a for a in manifest["assets"] if a["asset_type"] == "conversation")
    assert "cli" in conv["name"]


# --------------------------------------------------------------------------- #
# 端到端闭环
# --------------------------------------------------------------------------- #
def test_end_to_end_loop(tmp_path):
    home = tmp_path / "home"
    _make_claude_home(home)
    export_dir = tmp_path / "export"
    bundle = tmp_path / "bundle.ferry"
    session_md = tmp_path / "SESSION.md"

    rc = cli_main([
        "export", "--platform", "claude_code",
        "--account", str(home), "--out", str(export_dir),
    ])
    assert rc == 0
    assert (export_dir / "asset-manifest.json").exists()

    rc = cli_main([
        "package", "--input", str(export_dir),
        "--output", str(bundle), "--passphrase", "pw",
    ])
    assert rc == 0
    assert bundle.exists()

    rc = cli_main([
        "handoff", "--bundle", str(bundle),
        "--output", str(session_md), "--passphrase", "pw",
    ])
    assert rc == 0
    text = session_md.read_text(encoding="utf-8")
    assert "SESSION" in text
    assert "claude_code" in text
    # 解包目录里应有 manifest 且校验通过
    extract = bundle.parent / bundle.stem
    assert (extract / "asset-manifest.json").exists()


def test_validate_command(tmp_path):
    home = tmp_path / "home"
    _make_codex_home(home)
    export_dir = tmp_path / "export"
    cli_main(["export", "--platform", "codex", "--account", str(home),
              "--out", str(export_dir)])
    rc = cli_main(["validate", "--manifest", str(export_dir / "asset-manifest.json")])
    assert rc == 0


# --------------------------------------------------------------------------- #
# WorkBuddy 适配器（自研平台，合成 fixture）
# --------------------------------------------------------------------------- #
def _make_workbuddy_home(wb: Path):
    wb.mkdir(parents=True)
    (wb / "MEMORY.md").write_text(
        "长期记忆。\npassword = topsecretvalue123456\n", encoding="utf-8"
    )
    (wb / "USER.md").write_text("用户画像。\n", encoding="utf-8")
    (wb / "settings.json").write_text(
        json.dumps({"api_key": "sk-" + "z" * 32, "theme": "dark"}),
        encoding="utf-8",
    )
    mem = wb / "memory"
    mem.mkdir()
    (mem / "proj.md").write_text("项目记忆内容。\n", encoding="utf-8")
    skills = wb / "skills" / "demo-skill"
    skills.mkdir(parents=True)
    (skills / "SKILL.md").write_text(
        "技能说明。\ntoken: ghp_" + "b" * 36 + "\n", encoding="utf-8"
    )
    # automations 表（脱敏快照来源）
    import sqlite3
    db = wb / "workbuddy.db"
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE automations ("
        "id TEXT, name TEXT, prompt TEXT, scheduleType TEXT, "
        "rrule TEXT, status TEXT, modelId TEXT)"
    )
    conn.execute(
        "INSERT INTO automations VALUES (?,?,?,?,?,?,?)",
        ("auto-1", "每日简报",
         "每天早上发简报，password = secretpass999999",
         "recurring", "FREQ=DAILY", "ACTIVE", "gpt-5"),
    )
    conn.commit()
    conn.close()
    # 轻量项目索引来源
    (wb / "projects" / "alpha").mkdir(parents=True)
    (wb / "projects" / "beta").mkdir(parents=True)


def test_workbuddy_adapter(tmp_path):
    wb = tmp_path / "wb"
    _make_workbuddy_home(wb)
    out = tmp_path / "export"
    adapter = get_adapter("workbuddy")
    manifest = adapter.export(account=str(wb), out_dir=str(out))

    assert manifest["source"]["platform"] == "workbuddy"
    types = {a["asset_type"] for a in manifest["assets"]}
    assert "profile" in types
    assert "skill" in types
    assert "automation" in types

    # 脱敏：MEMORY.md 里的口令不应明文出现
    mem_text = (out / "workbuddy" / "MEMORY.md").read_text(encoding="utf-8")
    assert "topsecretvalue123456" not in mem_text
    # 新脱敏设计：凭据被抽出，原文替换为 «SECRET:{category}:{sid}» 占位
    assert "«SECRET:" in mem_text

    # 技能里的令牌被遮
    skill_text = (out / "workbuddy" / "skills" / "demo-skill" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    assert ("ghp_" + "b" * 36) not in skill_text

    # 自动化快照已导出且提示词脱敏
    auto_path = out / "workbuddy" / "automations.json"
    assert auto_path.exists()
    autos = json.loads(auto_path.read_text(encoding="utf-8"))
    assert len(autos) == 1
    assert "secretpass999999" not in autos[0]["prompt"]

    # 项目索引已导出
    assert (out / "workbuddy" / "project_index.json").exists()

    # manifest 符合 schema
    from handoff_kit.adapters.base import _SCHEMA_PATH
    import jsonschema
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    errs = list(jsonschema.Draft7Validator(schema).iter_errors(manifest))
    assert not errs, [e.message for e in errs]
