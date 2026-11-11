import base64
import hashlib
import hmac
import os
import secrets
import struct
import time


def hash_senha(senha, iteracoes=200_000):
    sal = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", senha.encode(), sal, iteracoes)
    return f"pbkdf2_sha256${iteracoes}${base64.b64encode(sal).decode()}${base64.b64encode(dk).decode()}"


def conferir_senha(senha, armazenado):
    try:
        _, it, sal_b64, dk_b64 = armazenado.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", senha.encode(), base64.b64decode(sal_b64), int(it))
        return hmac.compare_digest(dk, base64.b64decode(dk_b64))
    except (ValueError, AttributeError):
        return False


def gerar_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode()


def totp(secret, instante=None):
    chave = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    contador = int((time.time() if instante is None else instante) // 30)
    h = hmac.new(chave, struct.pack(">Q", contador), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def conferir_totp(secret, codigo):
    return any(hmac.compare_digest(totp(secret, time.time() + d * 30), str(codigo).zfill(6))
              for d in (-1, 0, 1))
