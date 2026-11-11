import csv
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from faker import Faker
from faker.utils.text import slugify

SEED = 2026
N_VOLUNTARIOS = 40
N_MORADORES = 200
N_PROFISSIONAIS_UBS = 15
DOMINIO = "vilaaurora.test"
TZ = timezone(timedelta(hours=-3))
FIM_HISTORICO = datetime(2026, 10, 31, 23, 59, tzinfo=TZ)
DIAS_HISTORICO = 30

ESPACOS = {
    "ubs": "UBS Vila Aurora",
    "escola": "Escola Municipal Vila Aurora",
    "centro": "Centro Comunitário",
    "horta": "Horta e Cozinha Solidária",
    "abrigo": "Abrigo de Emergência",
}
PORTAS = {
    "ubs": ["Entrada principal", "Sala de vacinas", "Farmácia"],
    "escola": ["Portão principal", "Casa de bombas", "Secretaria"],
    "centro": ["Entrada principal", "Sala de reuniões", "Almoxarifado"],
    "horta": ["Portão da horta", "Cozinha", "Depósito"],
    "abrigo": ["Entrada principal", "Dormitório", "Sala de gerador"],
}
FUNCOES_VOLUNTARIO = [
    "Apoio à cozinha", "Recepção", "Logística", "Apoio ao abrigo",
    "Horta", "Apoio escolar", "Manutenção",
]
CARGOS_UBS = (
    ["Médico(a)"] * 2 + ["Enfermeiro(a)"] * 3 + ["Técnico(a) de enfermagem"] * 5
    + ["Agente comunitário de saúde"] * 4 + ["Farmacêutico(a)"] * 1
)

fake = Faker("pt_BR")
Faker.seed(SEED)
rnd = random.Random(SEED)
usernames: set[str] = set()


def nome_completo(feminino: bool = False) -> str:
    primeiro = fake.first_name_female() if feminino else fake.first_name()
    return f"{primeiro} {fake.last_name()} {fake.last_name()}"


def _dv_cpf(digitos: list[int]) -> int:
    peso = len(digitos) + 1
    return (sum(d * (peso - i) for i, d in enumerate(digitos)) * 10) % 11 % 10


def cpf_valido(cpf: str) -> bool:
    d = [int(c) for c in cpf if c.isdigit()]
    return len(d) == 11 and d[9] == _dv_cpf(d[:9]) and d[10] == _dv_cpf(d[:10])


def cpf_sintetico() -> str:
    base = [rnd.randint(0, 9) for _ in range(9)]
    dv1 = _dv_cpf(base)
    dv2_invalido = (_dv_cpf(base + [dv1]) + 1) % 10
    d = "".join(map(str, base + [dv1, dv2_invalido]))
    return f"{d[:3]}.{d[3:6]}.{d[6:9]}-{d[9:]}"


def novo_username(nome: str) -> str:
    partes = slugify(nome).split("-")
    base = f"{partes[0]}.{partes[-1]}"
    candidato, n = base, 2
    while candidato in usernames:
        candidato, n = f"{base}{n}", n + 1
    usernames.add(candidato)
    return candidato


def uid_rfid() -> str:
    return ":".join(f"{rnd.randint(0, 255):02X}" for _ in range(7))


def gravar(destino: Path, nome: str, linhas: list[dict]) -> None:
    with open(destino / nome, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(linhas[0].keys()))
        w.writeheader()
        w.writerows(linhas)


def gerar_voluntarios() -> list[dict]:
    linhas = []
    for i in range(1, N_VOLUNTARIOS + 1):
        nome = nome_completo(feminino=(i == 1))
        username = novo_username(nome)
        linhas.append({
            "id": f"VOL{i:03d}",
            "nome": nome,
            "cpf": cpf_sintetico(),
            "email": f"{username}@{DOMINIO}",
            "telefone": fake.phone_number(),
            "espaco_principal": "centro" if i == 1 else rnd.choice(list(ESPACOS)),
            "funcao": "Coordenadora de voluntários" if i == 1 else rnd.choice(FUNCOES_VOLUNTARIO),
            "data_cadastro": fake.date_between(start_date="-3y", end_date="-30d").isoformat(),
            "_username": username,
        })
    return linhas


def gerar_moradores() -> list[dict]:
    linhas = []
    for i in range(1, N_MORADORES + 1):
        linhas.append({
            "id": f"MOR{i:03d}",
            "nome": nome_completo(),
            "cpf": cpf_sintetico(),
            "data_nascimento": fake.date_of_birth(minimum_age=0, maximum_age=95).isoformat(),
            "endereco": f"{fake.street_name()}, {fake.building_number()} - Vila Aurora, Serra Clara - SP",
            "telefone": fake.phone_number() if rnd.random() < 0.8 else "",
            "cadastro_cozinha_solidaria": rnd.random() < 0.35,
            "cadastro_abrigo": rnd.random() < 0.15,
        })
    return linhas


def gerar_profissionais() -> list[dict]:
    linhas = []
    cargos = CARGOS_UBS[:]
    rnd.shuffle(cargos)
    for i, cargo in enumerate(cargos, start=1):
        nome = nome_completo()
        username = novo_username(nome)
        if cargo == "Médico(a)":
            registro = f"CRM-SP {rnd.randint(100000, 299999)}"
        elif cargo == "Farmacêutico(a)":
            registro = f"CRF-SP {rnd.randint(10000, 99999)}"
        elif "nfermag" in cargo or cargo == "Enfermeiro(a)":
            registro = f"COREN-SP {rnd.randint(100000, 999999)}"
        else:
            registro = ""
        linhas.append({
            "id": f"UBS{i:03d}",
            "nome": nome,
            "cpf": cpf_sintetico(),
            "cargo": cargo,
            "registro_profissional": registro,
            "email": f"{username}@{DOMINIO}",
            "telefone": fake.phone_number(),
            "_username": username,
        })
    return linhas


def gerar_usuarios_painel(voluntarios: list[dict], profissionais: list[dict]) -> list[dict]:
    enfermeiros = [p for p in profissionais if p["cargo"] == "Enfermeiro(a)"]
    outros_prof = [p for p in profissionais if p not in enfermeiros[:1]]
    vols = voluntarios[1:]

    atribuicao = (
        [(voluntarios[0], "coordenacao"), (enfermeiros[0], "coordenacao"), (vols[0], "coordenacao")]
        + [(v, "tecnico") for v in vols[1:6]]
        + [(outros_prof[0], "auditor"), (vols[6], "auditor")]
        + [(v, "operador") for v in vols[7:22]]
        + [(p, "operador") for p in outros_prof[1:6]]
    )
    for v, perfil in atribuicao:
        if perfil == "tecnico" and v["id"].startswith("VOL"):
            v["funcao"] = "Manutenção técnica"

    return [{
        "username": pessoa["_username"],
        "nome": pessoa["nome"],
        "email": pessoa["email"],
        "perfil": perfil,
        "origem": pessoa["id"],
        "ativo": True,
    } for pessoa, perfil in atribuicao]


def gerar_crachas(voluntarios: list[dict], profissionais: list[dict], usuarios: list[dict]) -> list[dict]:
    perfil_por_origem = {u["origem"]: u["perfil"] for u in usuarios}
    linhas = []
    for pessoa in voluntarios + profissionais:
        perfil = perfil_por_origem.get(pessoa["id"])
        if perfil == "coordenacao":
            espacos = list(ESPACOS)
        elif pessoa["id"].startswith("UBS"):
            espacos = ["ubs"]
        elif perfil == "tecnico":
            espacos = sorted({pessoa["espaco_principal"], "escola", "abrigo"})
        else:
            espacos = sorted({pessoa["espaco_principal"], "centro"})
        linhas.append({
            "uid": uid_rfid(),
            "titular_id": pessoa["id"],
            "espacos_autorizados": ";".join(espacos),
            "emitido_em": fake.date_between(start_date="-2y", end_date="-60d").isoformat(),
            "valido_ate": "2027-12-31",
            "status": "ativo",
        })
    return linhas


def gerar_registros_acesso(crachas: list[dict]) -> list[dict]:
    linhas = []
    inicio = FIM_HISTORICO - timedelta(days=DIAS_HISTORICO)
    for c in crachas:
        autorizados = c["espacos_autorizados"].split(";")
        for d in range(DIAS_HISTORICO):
            if rnd.random() > 0.5:
                continue
            dia = inicio + timedelta(days=d)
            for _ in range(rnd.choice([1, 1, 2])):
                negado = rnd.random() < 0.02
                espaco = rnd.choice([e for e in ESPACOS if e not in autorizados] or autorizados) if negado \
                    else rnd.choice(autorizados)
                quando = dia.replace(hour=rnd.randint(7, 19), minute=rnd.randint(0, 59), second=rnd.randint(0, 59))
                linhas.append({
                    "data_hora": quando.isoformat(),
                    "cracha_uid": c["uid"],
                    "espaco": espaco,
                    "porta": rnd.choice(PORTAS[espaco]),
                    "resultado": "negado" if negado else "liberado",
                })
    linhas.sort(key=lambda r: r["data_hora"])
    for i, r in enumerate(linhas, start=1):
        r["id"] = i
    return [{"id": r["id"], **{k: v for k, v in r.items() if k != "id"}} for r in linhas]


def main() -> None:
    destino = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "output"
    destino.mkdir(parents=True, exist_ok=True)

    voluntarios = gerar_voluntarios()
    moradores = gerar_moradores()
    profissionais = gerar_profissionais()
    usuarios = gerar_usuarios_painel(voluntarios, profissionais)
    crachas = gerar_crachas(voluntarios, profissionais, usuarios)
    acessos = gerar_registros_acesso(crachas)

    sem_internos = lambda linhas: [{k: v for k, v in r.items() if not k.startswith("_")} for r in linhas]
    gravar(destino, "voluntarios.csv", sem_internos(voluntarios))
    gravar(destino, "moradores.csv", moradores)
    gravar(destino, "profissionais_ubs.csv", sem_internos(profissionais))
    gravar(destino, "usuarios_painel.csv", usuarios)
    gravar(destino, "crachas.csv", crachas)
    gravar(destino, "registros_acesso.csv", acessos)

    perfis = {}
    for u in usuarios:
        perfis[u["perfil"]] = perfis.get(u["perfil"], 0) + 1
    cpfs = [r["cpf"] for r in voluntarios + moradores + profissionais]
    resumo = "\n".join([
        f"DADOS SINTÉTICOS (Faker pt_BR, semente {SEED})",
        f"voluntarios.csv        {len(voluntarios)}",
        f"moradores.csv          {len(moradores)}",
        f"profissionais_ubs.csv  {len(profissionais)}",
        f"usuarios_painel.csv    {len(usuarios)}  {perfis}",
        f"crachas.csv            {len(crachas)}",
        f"registros_acesso.csv   {len(acessos)}",
        f"CPFs gerados: {len(cpfs)} | com dígito verificador válido: {sum(map(cpf_valido, cpfs))}",
    ])
    (destino / "_resumo.txt").write_text(resumo + "\n", encoding="utf-8")

if __name__ == "__main__":
    main()
