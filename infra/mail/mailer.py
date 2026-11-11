import os, smtplib, sys, time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
import dkim

TIPO = sys.argv[1]
MAILPIT = (os.environ.get("MAILPIT_HOST", "10.40.0.3"), int(os.environ.get("MAILPIT_PORT", "1025")))
SAIDA = os.environ.get("SAIDA", "/saida")
os.makedirs(SAIDA, exist_ok=True)

if TIPO == "legit":
    de, nome = "coordenacao@vilaaurora.test", "Coordenação Vila Aurora"
    assunto = "Reunião de voluntários desta semana"
    corpo = ("Olá! A reunião dos voluntários será na quinta, às 19h, no Centro Comunitário.\n"
             "Qualquer dúvida, respondam este e-mail. Abraços, Coordenação.")
else:
    de, nome = "secretaria@vilaaurora.test", "Secretaria Municipal"
    assunto = "ATUALIZAÇÃO OBRIGATÓRIA do acesso ao painel"
    corpo = ("Prezada, por seguranca atualize seu acesso ao painel AGORA em "
             "http://painel-prefeitura-serraclara.test/login antes que sua conta seja bloqueada.")

msg = EmailMessage()
msg["From"] = f"{nome} <{de}>"
msg["To"] = "coordenacao.voluntarios@vilaaurora.test"
msg["Subject"] = assunto
msg["Date"] = formatdate(localtime=True)
msg["Message-ID"] = make_msgid(domain="vilaaurora.test")
msg.set_content(corpo)

bruto = msg.as_bytes()
if TIPO == "legit":
    with open("/chaves/dkim.key") as f:
        chave = f.read()
    assinatura = dkim.sign(bruto, b"sel1", b"vilaaurora.test", chave.encode(),
                           include_headers=[b"from", b"to", b"subject", b"date"])
    bruto = assinatura + bruto

with open(os.path.join(SAIDA, f"{TIPO}.eml"), "wb") as f:
    f.write(bruto)

envelope = de
ip_origem = os.environ.get("IP_ORIGEM", "10.40.0.5") if TIPO == "legit" else "203.0.113.66"
with open(os.path.join(SAIDA, f"{TIPO}.meta"), "w") as f:
    f.write(f"{ip_origem}\n{envelope}\n")

for _ in range(10):
    try:
        s = smtplib.SMTP(*MAILPIT, timeout=10)
        s.send_message(msg, from_addr=envelope, to_addrs=["coordenacao.voluntarios@vilaaurora.test"])
        s.quit()
        break
    except OSError:
        time.sleep(2)
print(f"{TIPO}: enviado ao Mailpit | De: {de} | envelope(MAIL FROM): {envelope} | "
      f"DKIM: {'assinado' if TIPO=='legit' else 'ausente'}")
