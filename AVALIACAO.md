# Roteiro de avaliação — rubrica → comando → evidência

Guia para conferir cada critério da rubrica no ambiente. Para cada frase do nível **Excelente**, a
tabela indica o comando que a prova, o arquivo de evidência gerado em `docs/evidencias/` e o que
procurar nele. O ambiente precisa estar no ar (README, seção 2).

**Ordem sugerida:** `ntp` → C1 rápidos (`agente`, `failover`) → C2 → `painel` → C3 → C4 → C5
(`siem` antes de `deteccao`) → C6 (`llm preparar` uma vez antes de `llm testar`)
→ C8 → `caos 45` → `metricas` → `forense` (por último, para cobrir todas as evidências). O `caos` leva ~50 min; deixe o computador sem hibernar.

---

## C1 · Arquitetura resiliente e modular (RT-01 a RT-03) — 1,5 pt

| Rubrica | Comando | Evidência | O que procurar |
|---|---|---|---|
| Nó de borda autônomo por espaço | `agente` | `B08_agente_ubs.txt` | `"mqtt_conectado": true`, `"hub_online": true`, `"fila_pendente": 0`; tabela final com eventos dos 5 espaços (se aparecer `false` com os links no ar, ver "Se algo falhar") |
| Operação local comprovada | `caos 45` (ou `teste-local ubs 3`, versão curta) | `B30_caos.txt` (`B08_operacao_local_ubs.txt`) | Linha do tempo com `hub=False`, `fila` crescendo e `al=1`; `perda_dados_reconciliacao: 0`. No `B08_operacao_local_ubs.txt`, a linha `ALARME LOCAL ATIVADO` mostra o alarme decidido na borda com o hub inacessível |
| Redundância proporcional | `failover ubs` | `B09_failover_ubs.txt` | `LINK: FAILOVER fibra -> 4g` e depois `fibra restabelecida`; coluna `perdidos` = 0 |
| Trade-offs justificados | — | E1 | Tabela de decisões e trade-offs (seção 3) e plano de redundância proporcional (seção 4) |

## C2 · Identidade, VPN e segmentação (RT-04 a RT-07, RT-09) — 1,5 pt

| Rubrica | Comando | Evidência | O que procurar |
|---|---|---|---|
| Certificado único por dispositivo | `certs` | `B05_certs.txt` | `CN` do dispositivo, emissor `Vila Aurora Issuing CA`, validade de 90 dias, verificação `OK` |
| mTLS sem segredo compartilhado | `intruso` | `B06_mtls_ubs.txt` | Testes 1–3 recusados; teste 4 com `RC:135` / `Not authorized`; teste 5 (controle) aceito |
| Revogação demonstrada | `revogar ubs-ar-01` e, em seguida, `rotacionar ubs-ar-01` | `B07_revogacao_*.txt`, `B07_rotacao_*.txt` | `Revogado`, verificação `certificate revoked`, broker recusando; depois certificado novo `válido` e o antigo `REVOGADO` |
| VPN moderna | `vpn` | `B10_vpn.txt` | `latest handshake` recente; UBS → hub responde, UBS → Escola não; porta 8443 vinda de fora falha |
| Acesso administrativo com MFA | `bastion teste` | `B11_bastion_totp.txt` | Os 6 testes com `resultado: OK` (senha, chave errada, TOTP errado e reuso recusados; chave + TOTP válido aceito) |
| Segmentação efetiva | `segmentacao` | `B12_segmentacao.txt` | Matriz com todas as linhas `OK`; pacotes entre zonas negados > 0 |
| Nenhuma porta administrativa exposta | `varredura` | `B13_varredura_externa.txt` | `portas abertas: nenhuma`; `Portas publicadas no host pelo Docker: nenhuma` |
| MFA e perfis no painel | `rbac` | `B17_mfa_rbac.txt` | Sem o código MFA nenhuma tela abre; matriz de permissões por perfil |

## C3 · SQL Injection (RT-08) — 1,5 pt

Antes: `python tasks.py painel`.

| Rubrica | Comando | Evidência | O que procurar |
|---|---|---|---|
| Exploração demonstrada | `sqli` | `B14_sqli_exploracao.txt` | `parameter 'q' ... injectable`; operadores extraídos; agendamento da bomba alterado |
| Correção na causa raiz, com reteste | `reteste` | `B15_reteste_corrigido.txt` | `does not seem to be injectable`; `operadores vazados: 0`; `POST /bomba` 403; agendamento inalterado |
| Camada adicional (WAF) | `waf` | `B16_waf.txt` | `403 (Forbidden)`; regras do OWASP CRS acionadas (942xxx, 949110) |

## C4 · Phishing e fator humano (RT-10, RT-11, RT-18) — 1,5 pt

| Rubrica | Comando | Evidência | O que procurar |
|---|---|---|---|
| SPF/DKIM/DMARC corretos | `dns` | `B18_dns_email.txt` | Registros publicados; e-mail legítimo `dmarc=pass` → aceitar; forjado `dmarc=fail` → veredito de quarentena (o script registra o veredito; as duas mensagens chegam ao Mailpit) |
| Simulação ética com métricas | `phishing` | `B19_phishing.txt` | Enviados, abertos, cliques, submissões e reportes, só contas fictícias; e-mails no Mailpit (para vê-los no navegador, README, seção "Ver os e-mails da campanha") |
| Conscientização adaptada (voz clonada, verificação fora de banda) | — | E1 | Ameaças potencializadas por IA (seção 6) e orientação e plano de conscientização dos voluntários (seção 6.4) |

## C5 · Detecção, resposta e forense (RT-12 a RT-15) — 1,5 pt

| Rubrica | Comando | Evidência | O que procurar |
|---|---|---|---|
| Logs sincronizados | `ntp` | `B02_ntp.txt` | Fontes sincronizadas com o servidor NTP do hub |
| Logs centralizados | `siem` | `B21_siem.txt` | Eventos por fonte (dispositivos, broker, VPN, web, banco, SO) |
| Quatro regras funcionando | `deteccao` | `B22_deteccao.txt` | 4 linhas na tabela de alertas, cada uma com alertas > 0 e MTTD |
| Baixo risco automático, alto impacto com aprovação humana | `soar` | `B23_soar.txt` | Ações `baixo` registradas como `executado`; ação `alto` → `aguardando_aprovacao` e depois `aprovado_e_executado` com MFA. A fila registra a decisão, e a execução é feita pelos comandos `revogar` e `link` (E3, seção 10.2) |
| Linha do tempo no ATT&CK | `incidente` | `B24_incidente.txt` | Cadeia do INC-VA-0712 com hora, fase e técnica ATT&CK |
| Laudo com hash e custódia | `forense` (rodar por último) | `B25_forense.txt` | Tabela arquivo, bytes e SHA-256 de todas as evidências; laudo completo no E4 |

## C6 · IA & Cyber (RT-16 a RT-18) — 1 pt

| Rubrica | Comando | Evidência | O que procurar |
|---|---|---|---|
| IA defensiva com métricas medidas | `anomalia` | `B26_anomalia.txt` | Precisão, revocação, F1 e falsos positivos |
| Guardrails testados contra prompt injection | `llm preparar` (uma vez) e `llm testar` | `B27_llm_guardrails.txt` | 10 testes `=> PASSOU`; LLM só na rede `vila_ai` |
| OWASP LLM/ATLAS e ameaças por IA | — | E1 e E3 | Mapeamento OWASP LLM Top 10 / MITRE ATLAS (E3, seção 11) e tabela ameaça → controle (E1, seção 6.3) |

## C7 · Métricas e continuidade (RT-22, RT-23) — 0,5 pt

| Rubrica | Comando | Evidência | O que procurar |
|---|---|---|---|
| Teste de caos ≥ 30 min | `caos 45` | `B30_caos.txt` | Linha do tempo com `hub=False` nos 5 espaços durante a queda (43 min contados como operação autônoma), disponibilidade local 100% e perda 0. O MTTD calculado por este script tem uma limitação descrita no E1 (seção 7.1); o MTTD local de referência está no `B08_operacao_local_ubs.txt` |
| Todos os indicadores do RT-22 | `metricas` (depois do `caos`) | `B29_metricas.txt` | Disponibilidade, MTTD/MTTR, autonomia, perda, CPU, memória, banda e energia (sobre o MTTD, ver a linha anterior) |
| Análise crítica | — | E1 | Análise crítica das métricas e limitações (seção 7) |

## C8 · Custos, privacidade, acessibilidade e manutenção (RT-19 a RT-21) — 0,5 pt

| Rubrica | Comando | Evidência | O que procurar |
|---|---|---|---|
| RIPD coerente com a LGPD | `ripd` | `B31_pseudonimizacao.txt` | Registros de acesso com pseudônimo HMAC no lugar do identificador |
| Painel acessível | `wcag` | `B33_wcag.txt` | `TOTAL: criticos=0 serios=0` nas telas do painel |
| Custos e manutenção com responsáveis | — | E1 | Tabelas de custo de implantação e de 12 meses de operação e plano de manutenção (seção 9) |

## C9 · Comunicação e documentação — 0,5 pt

Ambiente reproduzível pelo README (seção 2), relatórios E1, E3 e E4 e vídeo de demonstração.

## Diferencial · OTA assinado

| Comando | Evidência | O que procurar |
|---|---|---|
| `ota` | `B34_ota.txt` | Pacote íntegro aplicado; pacote adulterado e chave não confiável recusados |

## Se algo falhar

| Sintoma | Causa provável | O que fazer |
|---|---|---|
| `B18_dns_email.txt` com `SERVFAIL` e `spf=temperror` | O CoreDNS subiu no `up all` antes de o arquivo do domínio existir | `docker restart coredns` e repetir o `dns` |
| `agente` com `"hub_online": false` mesmo com os links no ar, ou `anomalia` com 0 leituras | A ingestão do hub ficou presa à rede antiga da VPN do hub depois de esta ser recriada | `docker rm -f hub-ingest` e `python tasks.py up hub`; as filas das bordas são reenviadas sem perda |
| `B21_siem.txt` sem a fonte `vpn` | O coletor lê as últimas 3 h de log, e a VPN só registra eventos quando um link cai ou volta | Rodar o `siem` até 3 h depois de um `failover ubs` |
