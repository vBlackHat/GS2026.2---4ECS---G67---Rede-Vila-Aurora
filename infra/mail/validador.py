import os, re, sys
import dns.resolver
import spf
import dkim

TIPO = sys.argv[1]
SAIDA = os.environ.get("SAIDA", "/saida")
with open(os.path.join(SAIDA, f"{TIPO}.eml"), "rb") as f:
    bruto = f.read()
ip_origem, envelope = open(os.path.join(SAIDA, f"{TIPO}.meta")).read().split("\n")[:2]

cabecalho = bruto.split(b"\r\n\r\n")[0].split(b"\n\n")[0].decode("utf-8", "replace")
m = re.search(r"From:.*?<([^>]+)>", cabecalho, re.S)
dominio_from = (m.group(1) if m else "").split("@")[-1].strip().lower()
dominio_envelope = envelope.split("@")[-1].strip().lower()

res_spf = spf.check2(i=ip_origem, s=envelope, h="mail.atacante.invalido")[0]
spf_ok = res_spf == "pass"
spf_alinhado = spf_ok and dominio_envelope == dominio_from

try:
    dkim_ok = dkim.verify(bruto)
except Exception:
    dkim_ok = False
md = re.search(rb"DKIM-Signature:.*?d=([^;\s]+)", bruto, re.S)
dominio_dkim = (md.group(1).decode().strip().lower() if md else "")
dkim_alinhado = dkim_ok and dominio_dkim == dominio_from

try:
    dmarc_txt = "".join(s.decode() for r in dns.resolver.resolve(f"_dmarc.{dominio_from}", "TXT")
                        for s in r.strings)
    politica = re.search(r"p=(\w+)", dmarc_txt)
    politica = politica.group(1) if politica else "none"
except Exception:
    dmarc_txt, politica = "(sem registro DMARC)", "none"

dmarc_ok = (spf_ok and spf_alinhado) or (dkim_ok and dkim_alinhado)
acao = "aceitar" if dmarc_ok else {"quarantine": "quarentena", "reject": "rejeitar"}.get(politica, "aceitar")

print(f"=== {TIPO.upper()} === De: @{dominio_from} | origem IP: {ip_origem} | envelope: @{dominio_envelope}")
print(f"spf={res_spf} (alinhado={'sim' if spf_alinhado else 'nao'}) | "
      f"dkim={'pass' if dkim_ok else 'fail'} (d={dominio_dkim or '-'}, alinhado={'sim' if dkim_alinhado else 'nao'}) | "
      f"dmarc={'pass' if dmarc_ok else 'fail'}")
print(f"Authentication-Results: vilaaurora.test; spf={res_spf}; "
      f"dkim={'pass' if dkim_ok else 'fail'}; dmarc={'pass' if dmarc_ok else 'fail'} (p={politica}) -> {acao}")
