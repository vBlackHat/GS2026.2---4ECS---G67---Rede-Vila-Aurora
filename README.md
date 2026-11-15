# Rede Comunitária Vila Aurora — Infraestrutura Segura e Resiliente

**FIAP · Global Solution 2026.2 · Resilient Community Infrastructure**

Redesenho de segurança da infraestrutura da Rede Comunitária Vila Aurora (município fictício de
Serra Clara/SP) após o incidente **INC-VA-0712**: phishing com voz clonada → VPN sem MFA → SQL
Injection → alteração da bomba d'água → queda de link com a câmara fria de vacinas sem alerta.

A solução entrega uma arquitetura em camadas com **nó de borda autônomo** por espaço, identidade por
dispositivo (mTLS), VPN com MFA, segmentação, detecção/resposta (SIEM + SOAR), forense, IA defensiva
(detecção de anomalias + LLM local com guardrails) e privacidade por concepção — tudo com **software
livre** e **dados sintéticos**, em laboratório isolado.

**Grupo:** Kenzo Schiavone Inoue dos Santos (RM99890) · Pedro Daniluz (RM97697)

---

## 1. Pré-requisitos

- **Windows 10/11** com **Docker Desktop** instalado e em execução (inclui o Docker Compose v2).
- Recomendado **16 GB de RAM** disponíveis para o Docker (mínimo ~8 GB).
- **Python 3.11+** no Windows (o orquestrador `tasks.py` usa apenas a biblioteca padrão).
- Comandos executados no **PowerShell**, na raiz do repositório.
- Acesso à internet apenas para **baixar as imagens** (passo `pull`); a operação em si roda offline.

Confira o ambiente:

```bash
python tasks.py check
```

## 2. Subir o ambiente do zero

Execute na ordem (cada passo é idempotente):

```bash
python tasks.py init        # 1. gera o .env com segredos aleatórios
python tasks.py sysctl      # 2. ajusta vm.max_map_count (uma vez por boot do Docker)
python tasks.py pull        # 3. baixa as imagens e o modelo do LLM (llama3.2:3b)
python tasks.py data        # 4. gera os dados sintéticos (Faker pt_BR)
python tasks.py pki         # 5. cria a CA e emite os certificados por dispositivo
python tasks.py wg          # 6. gera as chaves e configs WireGuard (hub + 5 espaços)
python tasks.py acesso      # 7. gera as chaves SSH do bastion e o segredo TOTP
python tasks.py up all      # 8. sobe o hub e os 5 nós de borda
```

Ao final, `python tasks.py status` deve listar os contêineres do projeto no ar. Para derrubar tudo:
`python tasks.py down all`.

> Os segredos (`.env`, chaves, certificados, credenciais) ficam em pastas `out/` e **nunca são
> versionados** (ver `.gitignore`). Cada clone gera os seus próprios.

## 3. Demonstração por critério de avaliação

Cada comando executa a prova e salva a evidência em `docs/evidencias/`.

| Critério | Comando(s) | O que demonstra |
|----------|-----------|-----------------|
| **C1** Arquitetura resiliente | `agente`, `failover ubs`, `caos 45` | Nó de borda autônomo, failover 4G, operação offline + reconciliação |
| **C2** Identidade/VPN/segmentação | `certs`, `intruso`, `revogar <disp>`, `rotacionar <disp>`, `vpn`, `bastion teste`, `segmentacao`, `varredura` | mTLS por dispositivo, revogação, VPN+MFA, zonas, nenhuma porta admin exposta |
| **C3** SQL Injection | `sqli`, `reteste`, `waf` | Exploração → correção na causa raiz → WAF |
| **C4** Phishing | `dns`, `phishing`, `cartilha` | SPF/DKIM/DMARC, campanha simulada + métricas, conscientização |
| **C5** Detecção/resposta/forense | `siem`, `deteccao`, `soar`, `incidente`, `forense` | SIEM, 4 regras + MTTD, SOAR com aprovação humana, laudo forense |
| **C6** IA & Cyber | `anomalia`, `llm` | Isolation Forest com métricas; LLM local com guardrails (10 testes) |
| **C7** Métricas/continuidade | `caos 45`, `metricas` | Disponibilidade, MTTD/MTTR, operação autônoma, perda de dados, recursos |
| **C8** Custos/privacidade/acessib. | `ripd`, `wcag` | Pseudonimização HMAC; auditoria WCAG 2.1 AA do painel |
| **Diferenciais** | `ota` | Atualização OTA assinada com Ed25519 (aceita íntegra, recusa adulterada) |

Exemplo:

```bash
python tasks.py sqli        # explora o painel vulnerável
python tasks.py reteste     # repete contra o painel corrigido (bloqueado)
python tasks.py caos 45     # teste de caos de 45 minutos
```

## 4. Estrutura do repositório

```
tasks.py                 Orquestrador (um comando por prova). python tasks.py -h lista tudo.
infra/                   Compose (hub e borda), nftables, WireGuard, DNS, mail, OTA, WCAG, etc.
panel/                   Painel de supervisão (Flask): versões vulnerável e corrigida, RBAC, MFA.
edge/                    Agente de borda (store-and-forward), simulador de sensores.
pki/                     Scripts da CA / PKI do projeto.
ai/anomaly/              Detecção de anomalias (Isolation Forest).
ai/llm-assistant/        Assistente LLM + guardrails + testes de injeção.
data/                    Geração de dados sintéticos (Faker pt_BR).
docs/evidencias/         Evidências geradas por cada comando.
docs/relatorios/         Seções e PDFs dos relatórios (E1, E3, E4).
```

## 5. Segurança, ética e privacidade

- **Dados exclusivamente sintéticos** (Faker pt_BR). Nenhum dado pessoal real em código, logs ou relatórios (LGPD).
- **Laboratório isolado:** toda atividade ofensiva (sqlmap, Gophish, testes de injeção no LLM) ocorre apenas no ambiente próprio, contra alvos fictícios (Lei 12.737/2012).
- **Sem segredos versionados:** chaves, certificados, `.env` e credenciais são gerados localmente e ignorados pelo Git.
- **IA de apoio declarada:** ver a seção "Uso de IA" no relatório E1.
