import csv, json, os, random, sqlite3, time, urllib.error, urllib.parse, urllib.request

API = "http://10.40.0.4:3333/api"
PHISH = "http://10.40.0.4:8080"
DB = "/data/gophish.db"
rnd = random.Random(2026)


def chave():
    for _ in range(30):
        try:
            k = sqlite3.connect(DB).execute(
                "SELECT api_key FROM users WHERE username='admin'").fetchone()
            if k and k[0]:
                return k[0]
        except sqlite3.Error:
            pass
        time.sleep(2)
    raise SystemExit("não consegui ler a api_key do Gophish")


KEY = chave()


def call(metodo, caminho, corpo=None):
    url = f"{API}{caminho}"
    url += ("&" if "?" in url else "?") + f"api_key={KEY}"
    dados = json.dumps(corpo).encode() if corpo is not None else None
    req = urllib.request.Request(url, data=dados, method=metodo,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or "null")
    except urllib.error.HTTPError as e:
        return {"erro": e.code, "detalhe": e.read().decode()[:200]}


def limpar(caminho, nomes):
    for item in call("GET", caminho) or []:
        if isinstance(item, dict) and item.get("name") in nomes:
            call("DELETE", f"{caminho}{item['id']}")


ALVOS = []
with open("/dados/voluntarios.csv", encoding="utf-8") as f:
    for v in list(csv.DictReader(f))[:30]:
        nome = v["nome"].split()
        ALVOS.append({"first_name": nome[0], "last_name": " ".join(nome[1:]),
                      "email": v["email"], "position": v["funcao"]})

for c, nomes in [("/campaigns/", {"Campanha Vila Aurora"}), ("/groups/", {"Voluntários (fictícios)"}),
                 ("/templates/", {"Atualização obrigatória"}), ("/pages/", {"Login Prefeitura (falso)"}),
                 ("/smtp/", {"Mailpit Lab"})]:
    limpar(c, nomes)

def criar(caminho, corpo, rotulo):
    r = call("POST", caminho, corpo)
    if isinstance(r, dict) and r.get("erro"):
        raise SystemExit(f"falha em {rotulo}: {r}")
    print(f"  {rotulo}: ok")
    return r

criar("/smtp/", {"name": "Mailpit Lab", "host": "10.40.0.3:1025",
     "from_address": "secretaria@vilaaurora.test",
     "ignore_cert_errors": True, "interface_type": "SMTP"}, "perfil SMTP")
criar("/pages/", {"name": "Login Prefeitura (falso)", "capture_credentials": True,
     "capture_passwords": True, "redirect_url": "http://vilaaurora.test/",
     "html": "<html><body><h2>Portal da Prefeitura - Serra Clara</h2>"
             "<form method='post'>Usuário:<input name='username'><br>Senha:"
             "<input name='password' type='password'><br><button>Entrar</button></form></body></html>"}, "página falsa")
criar("/templates/", {"name": "Atualização obrigatória",
     "subject": "ATUALIZAÇÃO OBRIGATÓRIA do acesso ao painel",
     "html": "<html><body><p>Prezado(a) {{.FirstName}},</p><p>Por determinação da Secretaria, "
             "atualize seu acesso ao painel em até 24h ou sua conta será bloqueada.</p>"
             "<p><a href='{{.URL}}'>Atualizar meu acesso agora</a></p>"
             "<p>Secretaria Municipal de Serra Clara.</p>{{.Tracker}}</body></html>",
     "text": "Atualize seu acesso em {{.URL}} em ate 24h."}, "template de e-mail")
criar("/groups/", {"name": "Voluntários (fictícios)", "targets": ALVOS}, "grupo de alvos")

lanc = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
camp = call("POST", "/campaigns/", {"name": "Campanha Vila Aurora",
     "template": {"name": "Atualização obrigatória"}, "page": {"name": "Login Prefeitura (falso)"},
     "smtp": {"name": "Mailpit Lab"}, "url": PHISH, "launch_date": lanc,
     "groups": [{"name": "Voluntários (fictícios)"}]})
cid = camp.get("id")
if not cid:
    raise SystemExit(f"falha ao criar campanha: {camp}")
print(f"Campanha criada (id {cid}) com {len(ALVOS)} alvos fictícios. Aguardando envio...")
time.sleep(12)

class SemRedir(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

op_funil = urllib.request.build_opener(SemRedir)


def hit(url, data=None):
    try:
        op_funil.open(urllib.request.Request(url, data=data), timeout=10).read()
    except Exception:
        pass


res = call("GET", f"/campaigns/{cid}/results")
alvos = res.get("results", [])
abriram = cliques = enviaram = 0
for r in alvos:
    rid = r.get("id")
    if not rid or rnd.random() > 0.6:
        continue
    hit(f"{PHISH}/track?rid={rid}"); abriram += 1
    if rnd.random() < 0.5:
        hit(f"{PHISH}/?rid={rid}"); cliques += 1
        if rnd.random() < 0.5:
            d = urllib.parse.urlencode({"username": r.get("email", "").split("@")[0],
                                        "password": "VilaAurora123"}).encode()
            hit(f"{PHISH}/?rid={rid}", d); enviaram += 1
time.sleep(4)

reportaram = 0
con = sqlite3.connect(DB)
for r in alvos:
    if r.get("status") in ("Email Sent", "Email Opened") and rnd.random() < 0.3:
        con.execute("UPDATE results SET reported=1 WHERE campaign_id=? AND id=?", (cid, r["id"]))
        reportaram += 1
con.commit()

s = call("GET", f"/campaigns/{cid}/summary").get("stats", {})
print(f"Métricas da campanha (n={len(alvos)}):")
print(f"  enviados   : {s.get('sent', 0)}")
print(f"  abertos    : {s.get('opened', 0)}  (simulados: {abriram})")
print(f"  cliques    : {s.get('clicked', 0)}  (simulados: {cliques})")
print(f"  submeteram : {s.get('submitted_data', 0)}  (credenciais capturadas)")
print(f"  reportaram : {reportaram}  (marcados como denúncia ao SOC)")
