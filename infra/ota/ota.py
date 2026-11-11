"""
B34 - Demonstração de atualização OTA assinada com Ed25519.

A autoridade de atualização assina o pacote de firmware com a chave privada Ed25519.
O dispositivo de campo traz embarcada apenas a chave pública e só aplica o pacote se a
assinatura conferir. Mostra três casos: pacote íntegro (aceito), pacote adulterado (recusado)
e pacote assinado por uma chave não confiável (recusado).
"""
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

saida = os.environ.get("SAIDA", "/saida")
os.makedirs(saida, exist_ok=True)
priv_path = os.path.join(saida, "ota_signing.key")

if os.path.exists(priv_path):
    with open(priv_path, "rb") as f:
        priv = Ed25519PrivateKey.from_private_bytes(f.read())
else:
    priv = Ed25519PrivateKey.generate()
    bruto = priv.private_bytes(serialization.Encoding.Raw,
                               serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
    with open(priv_path, "wb") as f:
        f.write(bruto)

pub = priv.public_key()
pub_hex = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

# Pacote de firmware fictício (versão + conteúdo determinístico)
firmware = b"VILA-AURORA-FW v2.1.0 :: agente de borda\n" + bytes(range(256)) * 8
assinatura = priv.sign(firmware)

print("=== OTA assinado (Ed25519) ===")
print(f"Versao do pacote : VILA-AURORA-FW v2.1.0")
print(f"Tamanho firmware : {len(firmware)} bytes")
print(f"Chave publica (embarcada no dispositivo): {pub_hex}")
print(f"Assinatura (64 bytes, hex): {assinatura.hex()}")


def dispositivo_verifica(nome: str, blob: bytes, sig: bytes) -> bool:
    try:
        pub.verify(sig, blob)
        print(f"[{nome}] assinatura VALIDA  -> dispositivo APLICA a atualizacao")
        return True
    except InvalidSignature:
        print(f"[{nome}] assinatura INVALIDA -> dispositivo RECUSA a atualizacao")
        return False


print("\n--- Caso 1: pacote oficial integro ---")
c1 = dispositivo_verifica("pacote-oficial", firmware, assinatura)

print("\n--- Caso 2: pacote adulterado (1 byte alterado em transito) ---")
adulterado = bytearray(firmware)
adulterado[10] ^= 0x01
c2 = dispositivo_verifica("pacote-adulterado", bytes(adulterado), assinatura)

print("\n--- Caso 3: pacote assinado por chave nao confiavel (atacante) ---")
atacante = Ed25519PrivateKey.generate()
c3 = dispositivo_verifica("assinatura-falsa", firmware, atacante.sign(firmware))

ok = c1 and (not c2) and (not c3)
print(f"\nResultado: {'OK - apenas o pacote oficial e aplicado' if ok else 'FALHA'}")
