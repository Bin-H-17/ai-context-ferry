"""加密信封（ferry-crypt v1）。

设计取舍（来自产品负责人授权：兼顾效率 / 方便性 / 安全性，以"丝滑切换"优先）：
- 复用业界验证过的原语，而非自造加密算法：
  * AES-256-GCM 提供机密性 + 完整性（防篡改），来自 `cryptography`。
  * 口令模式用 Argon2id（2015 密码哈希竞赛冠军，抗 GPU/ASIC）做密钥派生。
  * 收件人模式用 X25519 ECDH + HKDF 做密钥协商（与 age 的 X25519 思路一致）。
- 默认「口令模式」：零密钥基础设施，最丝滑，适合个人在多账号/多设备间无缝迁移。
- 可选「收件人模式」：用对方 X25519 公钥加密，最适合"把资产包交给另一个账号/人"，
  对方用自己私钥解密，无需共享口令。
- 信封为自描述 JSON，便于调试与跨语言解析；密文本身仍是标准 AES-GCM 输出。

参考：
- age (FiloSottile) 的"passphrase(scrypt) / recipient(X25519)"双模式设计 —— 思路借鉴，IETF 风格。
- cryptography 官方 AES-GCM / Argon2id / X25519 文档。
"""
from __future__ import annotations

import base64
import json
import os
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ENVELOPE_VERSION = "1.0"
FERRY_INFO = b"ai-context-ferry/ferry-crypt"

# Argon2id 参数（在"安全"与"解锁速度"间取平衡：约 1s / 64MiB）
# 注意：cryptography 的 Argon2id 直接收 iterations/lanes/memory_cost 关键字，
# 且 memory_cost 单位为 KiB（64 MiB = 65536 KiB）。
_ARGON_TIME_COST = 3
_ARGON_MEMORY_COST = 64 * 1024  # 65536 KiB = 64 MiB
_ARGON_PARALLELISM = 4
_NONCE_LEN = 12
_SALT_LEN = 16


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _derive_key_passphrase(passphrase: str, salt: bytes) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=_ARGON_TIME_COST,
        lanes=_ARGON_PARALLELISM,
        memory_cost=_ARGON_MEMORY_COST,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _derive_key_recipient(shared_secret: bytes, salt: bytes) -> bytes:
    hk = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=FERRY_INFO,
    )
    return hk.derive(shared_secret)


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    nonce = os.urandom(_NONCE_LEN)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return nonce, ct, enc.tag


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    return dec.update(ct) + dec.finalize()


def generate_x25519_keypair() -> Tuple[str, str]:
    """生成收件人密钥对，返回 (public_b64, private_b64)。"""
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    pub_b64 = _b64e(pub.public_bytes_raw())
    priv_b64 = _b64e(priv.private_bytes_raw())
    return pub_b64, priv_b64


def encrypt_bytes(
    data: bytes,
    passphrase: Optional[str] = None,
    recipient_pub_b64: Optional[str] = None,
) -> bytes:
    """加密字节流为 ferry-crypt 信封（JSON 文本）。

    必须提供 passphrase 或 recipient_pub_b64 之一。
    """
    if not passphrase and not recipient_pub_b64:
        raise ValueError("必须提供 passphrase 或 recipient_pub_b64 之一")

    if passphrase:
        salt = os.urandom(_SALT_LEN)
        key = _derive_key_passphrase(passphrase, salt)
        nonce, ct, tag = _aes_gcm_encrypt(key, data)
        envelope = {
            "ferry_crypt": ENVELOPE_VERSION,
            "mode": "passphrase",
            "kdf": {
                "alg": "argon2id",
                "salt": _b64e(salt),
                "time_cost": _ARGON_TIME_COST,
                "memory_cost": _ARGON_MEMORY_COST,
                "parallelism": _ARGON_PARALLELISM,
            },
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ct + tag),
        }
    else:
        salt = os.urandom(_SALT_LEN)
        eph_priv = X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key()
        recip_pub = X25519PublicKey.from_public_bytes(_b64d(recipient_pub_b64))
        shared = eph_priv.exchange(recip_pub)
        key = _derive_key_recipient(shared, salt)
        nonce, ct, tag = _aes_gcm_encrypt(key, data)
        envelope = {
            "ferry_crypt": ENVELOPE_VERSION,
            "mode": "recipient",
            "recipient": {
                "ephemeral_pub": _b64e(eph_pub.public_bytes_raw()),
                "salt": _b64e(salt),
            },
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ct + tag),
        }
    return json.dumps(envelope, ensure_ascii=False).encode("utf-8")


def decrypt_bytes(
    blob: bytes,
    passphrase: Optional[str] = None,
    identity_priv_b64: Optional[str] = None,
) -> bytes:
    """解密 ferry-crypt 信封。口令模式传 passphrase；收件人模式传 identity_priv_b64。"""
    env = json.loads(blob.decode("utf-8"))
    mode = env.get("mode")
    nonce = _b64d(env["nonce"])
    ct_tag = _b64d(env["ciphertext"])
    tag = ct_tag[-16:]
    ct = ct_tag[:-16]

    if mode == "passphrase":
        if not passphrase:
            raise ValueError("该包为口令模式，需要提供 --passphrase")
        kdf = env["kdf"]
        salt = _b64d(kdf["salt"])
        key = Argon2id(
            salt=salt,
            length=32,
            iterations=kdf["time_cost"],
            lanes=kdf["parallelism"],
            memory_cost=kdf["memory_cost"],
        ).derive(passphrase.encode("utf-8"))
    elif mode == "recipient":
        if not identity_priv_b64:
            raise ValueError("该包为收件人模式，需要提供 --identity（私钥）")
        recip = env["recipient"]
        salt = _b64d(recip["salt"])
        eph_pub = X25519PublicKey.from_public_bytes(_b64d(recip["ephemeral_pub"]))
        priv = X25519PrivateKey.from_private_bytes(_b64d(identity_priv_b64))
        shared = priv.exchange(eph_pub)
        key = _derive_key_recipient(shared, salt)
    else:
        raise ValueError(f"未知加密模式: {mode}")

    return _aes_gcm_decrypt(key, nonce, ct, tag)


def encrypt_file(
    src: str,
    dst: str,
    passphrase: Optional[str] = None,
    recipient_pub_b64: Optional[str] = None,
) -> None:
    with open(src, "rb") as f:
        data = f.read()
    out = encrypt_bytes(data, passphrase=passphrase, recipient_pub_b64=recipient_pub_b64)
    with open(dst, "wb") as f:
        f.write(out)


def decrypt_file(
    src: str,
    dst: str,
    passphrase: Optional[str] = None,
    identity_priv_b64: Optional[str] = None,
) -> None:
    with open(src, "rb") as f:
        blob = f.read()
    data = decrypt_bytes(blob, passphrase=passphrase, identity_priv_b64=identity_priv_b64)
    with open(dst, "wb") as f:
        f.write(data)


def public_key_from_private(private_b64: str) -> str:
    """由私钥推导公钥（用于校验/展示）。"""
    priv = X25519PrivateKey.from_private_bytes(_b64d(private_b64))
    return _b64e(priv.public_key().public_bytes_raw())


# --------------------------------------------------------------------------- #
# 凭据保险库（secret vault）：把抽取出的敏感凭据单独加密，与明文资产分离。
# --------------------------------------------------------------------------- #
def encrypt_vault(
    secrets: list,
    passphrase: Optional[str] = None,
    recipient_pub_b64: Optional[str] = None,
) -> bytes:
    """把凭据记录列表加密为 ferry-crypt 信封（JSON 文本）。

    与 `encrypt_bytes` 同语义，仅约定载荷为 secrets JSON。
    """
    payload = json.dumps(secrets, ensure_ascii=False).encode("utf-8")
    return encrypt_bytes(payload, passphrase=passphrase, recipient_pub_b64=recipient_pub_b64)


def decrypt_vault(
    blob: bytes,
    passphrase: Optional[str] = None,
    identity_priv_b64: Optional[str] = None,
) -> list:
    """解密凭据保险库，返回凭据记录列表。"""
    data = decrypt_bytes(blob, passphrase=passphrase, identity_priv_b64=identity_priv_b64)
    return json.loads(data.decode("utf-8"))
