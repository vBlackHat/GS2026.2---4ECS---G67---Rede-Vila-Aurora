import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DEST = os.environ.get("CHAVES", "/chaves")
os.makedirs(DEST, exist_ok=True)
priv_path = os.path.join(DEST, "dkim.key")

if os.path.exists(priv_path):
    with open(priv_path, "rb") as f:
        chave = serialization.load_pem_private_key(f.read(), password=None)
else:
    chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(priv_path, "wb") as f:
        f.write(chave.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

pub = chave.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
import base64
p = base64.b64encode(pub).decode()
registro = "v=DKIM1; k=rsa; p=" + p
partes = [registro[i:i + 200] for i in range(0, len(registro), 200)]
linha = 'sel1._domainkey IN TXT ' + ' '.join(f'"{x}"' for x in partes)
print(linha)
