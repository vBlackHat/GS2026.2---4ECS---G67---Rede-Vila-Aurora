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
- Acesso à internet para **baixar as imagens** (passo `pull`) e as bibliotecas usadas na geração de dados e na construção de algumas imagens; a operação em si roda offline.

Confira o ambiente:

```bash
python tasks.py check
```

## 2. Subir o ambiente do zero

Execute na ordem (cada passo é idempotente):

```bash
python tasks.py init        # 1. gera o .env com segredos aleatórios
python tasks.py pull        # 2. baixa as imagens e o modelo do LLM (llama3.2:3b)
python tasks.py data        # 3. gera os dados sintéticos (Faker pt_BR)
python tasks.py pki         # 4. cria a CA e emite os certificados por dispositivo
python tasks.py wg          # 5. gera as chaves e configs WireGuard (hub + 5 espaços)
python tasks.py acesso      # 6. gera as chaves SSH do bastion e o segredo TOTP
python tasks.py up all      # 7. sobe o hub e os 5 nós de borda
python tasks.py painel      # 8. carrega o banco do painel e sobe os painéis (vulnerável e corrigido) e o WAF
python tasks.py llm preparar  # 9. prepara o assistente de IA local (usado no C6)
```

Ao final, `python tasks.py status` deve listar os contêineres do projeto no ar. Para derrubar tudo:
`python tasks.py down all`.

> Os segredos (`.env`, chaves, certificados, credenciais) ficam em pastas `out/` e **nunca são
> versionados** (ver `.gitignore`). Cada clone gera os seus próprios.

### Ver o painel no navegador (opcional)

Por segurança, nenhuma porta do laboratório é publicada no Windows: o painel só existe na rede interna
`vila_ops`. Para abri-lo no navegador, crie um acesso temporário, restrito a este computador:

```powershell
docker run --rm -d --name ver-painel --network vila_ops -p 127.0.0.1:8080:8080 -e PORT=8080 -e BACKEND=http://10.30.2.20:8000 owasp/modsecurity-crs:nginx-alpine
```

1. Acesse **http://localhost:8080** e entre com um usuário de `panel/out/credenciais.txt` (formato
   `usuário | senha | perfil | segredo TOTP`; o perfil `coordenacao` vê todos os menus).
2. Para o código MFA, cadastre o segredo TOTP em um app autenticador no celular (Google ou Microsoft
   Authenticator → adicionar conta → inserir chave de configuração, tipo baseado em tempo) e digite o
   código de 6 dígitos exibido.
3. Ao terminar, encerre com `docker stop ver-painel`.

### Ver os e-mails da campanha (opcional)

O Mailpit, caixa de entrada de teste dos e-mails do domínio fictício, também fica só na rede interna
`vila_lab`. O acesso temporário segue a mesma ideia do painel; como essa rede não permite publicar
portas, o contêiner sobe na rede padrão e depois é ligado a ela:

```powershell
docker run --rm -d --name ver-email -p 127.0.0.1:8025:8080 -e PORT=8080 -e BACKEND=http://10.40.0.3:8025 -e MODSEC_RULE_ENGINE=Off owasp/modsecurity-crs:nginx-alpine
docker network connect vila_lab ver-email
```

Acesse **http://localhost:8025**. Os dois e-mails do teste de SPF/DKIM/DMARC aparecem depois do
`dns`, e os 30 da campanha simulada depois do `phishing`. Se a lista não atualizar sozinha, recarregue
a página. Ao terminar, encerre com `docker stop ver-email`.

## 3. Demonstração por critério de avaliação

Cada comando executa a prova e salva a evidência em `docs/evidencias/`.

| Critério | Comando(s) | Evidência | O que demonstra |
|----------|-----------|-----------|-----------------|
| **C1** Arquitetura resiliente | `agente`, `failover ubs`, `caos 45` | B08, B09, B30 | Nó de borda autônomo, failover 4G, operação offline + reconciliação |
| **C2** Identidade/VPN/segmentação | `certs`, `intruso`, `revogar <disp>`, `rotacionar <disp>`, `vpn`, `bastion teste`, `segmentacao`, `varredura`, `rbac` | B05–B07, B10–B13, B17 | mTLS por dispositivo, revogação, VPN+MFA, zonas, nenhuma porta admin exposta, MFA e perfis no painel |
| **C3** SQL Injection | `sqli`, `reteste`, `waf` | B14–B16 | Exploração → correção na causa raiz → WAF |
| **C4** Phishing | `dns`, `phishing` | B18, B19 | SPF/DKIM/DMARC, campanha simulada + métricas |
| **C5** Detecção/resposta/forense | `ntp`, `siem`, `deteccao`, `soar`, `incidente`, `forense` | B02, B21–B25 | Logs sincronizados, SIEM, 4 regras + MTTD, SOAR com aprovação humana, laudo forense |
| **C6** IA & Cyber | `anomalia`, `llm` | B26, B27 | Isolation Forest com métricas; LLM local com guardrails (10 testes) |
| **C7** Métricas/continuidade | `caos 45`, `metricas` | B30, B29 | Disponibilidade, MTTD/MTTR, operação autônoma, perda de dados, recursos |
| **C8** Custos/privacidade/acessib. | `ripd`, `wcag` | B31, B33 | Pseudonimização HMAC; auditoria WCAG 2.1 AA do painel |
| **Diferenciais** | `ota` | B34 | Atualização OTA assinada com Ed25519 (aceita íntegra, recusa adulterada) |

O passo a passo de cada critério (o que a rubrica pede, qual comando prova e o que procurar em cada
evidência) está em [`AVALIACAO.md`](AVALIACAO.md).

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
edge/                    Agente de borda (store-and-forward e regras locais).
devices/                 Inventário e simulador dos dispositivos de cada espaço.
hub/                     Serviço de ingestão do hub (HTTPS com mTLS, só no túnel).
pki/                     Scripts da CA / PKI do projeto.
ai/anomaly/              Detecção de anomalias (Isolation Forest).
ai/llm-assistant/        Assistente LLM + guardrails + testes de injeção.
data/                    Geração de dados sintéticos (Faker pt_BR).
docs/evidencias/         Evidências geradas por cada comando (local, fora do Git).
```

## 5. Segurança, ética e privacidade

- **Dados exclusivamente sintéticos** (Faker pt_BR). Nenhum dado pessoal real em código, logs ou relatórios (LGPD).
- **Laboratório isolado:** toda atividade ofensiva (sqlmap, Gophish, testes de injeção no LLM) ocorre apenas no ambiente próprio, contra alvos fictícios (Lei 12.737/2012).
- **Sem segredos versionados:** chaves, certificados, `.env` e credenciais são gerados localmente e ignorados pelo Git.
- **IA de apoio declarada:** ver a seção "Uso de IA" no relatório E1.
