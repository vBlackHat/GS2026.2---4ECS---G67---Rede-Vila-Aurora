import csv
import os
import secrets as _secrets
from pathlib import Path

import psycopg

import seguranca

DADOS = Path(os.environ.get("DADOS", "/dados"))
SAIDA = Path(os.environ.get("SAIDA", "/out"))
ADMIN = dict(host=os.environ.get("PGHOST", "hub-postgres"),
             user=os.environ.get("PGUSER", "vila_admin"),
             password=os.environ["PGPASSWORD"])
SENHA_APP = os.environ["SENHA_APP"]
SENHA_RO = os.environ["SENHA_RO"]


def ler(nome):
    with open(DADOS / nome, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    with psycopg.connect(dbname="postgres", autocommit=True, **ADMIN) as c:
        existe = c.execute("SELECT 1 FROM pg_database WHERE datname='painel'").fetchone()
        if not existe:
            c.execute("CREATE DATABASE painel")

    esquema = (Path(__file__).parent / "db" / "esquema.sql").read_text(encoding="utf-8")
    esquema = esquema.replace(":'SENHA_APP'", f"'{SENHA_APP}'").replace(":'SENHA_RO'", f"'{SENHA_RO}'")

    with psycopg.connect(dbname="painel", autocommit=True, **ADMIN) as c:
        c.execute(esquema)
        for t in ("auditoria", "agendamentos_bomba", "registros_acesso", "operadores"):
            c.execute(f"TRUNCATE {t} RESTART IDENTITY")

        nomes = {v["id"]: v["nome"] for v in ler("voluntarios.csv")}
        nomes.update({p["id"]: p["nome"] for p in ler("profissionais_ubs.csv")})
        titular_por_uid = {cr["uid"]: cr["titular_id"] for cr in ler("crachas.csv")}

        usuarios = ler("usuarios_painel.csv")
        linhas_cred = ["# Credenciais sintéticas do painel (fora do versionamento)",
                       "# usuario | senha | perfil | totp_secret", ""]
        exemplo = {}
        with c.cursor() as cur:
            for u in usuarios:
                senha = "va-" + seguranca.hashlib.sha256((u["username"] + "2026").encode()).hexdigest()[:10]
                secret = seguranca.gerar_totp_secret()
                cur.execute(
                    "INSERT INTO operadores (username, nome, email, perfil, senha_hash, totp_secret, ativo) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (u["username"], u["nome"], u["email"], u["perfil"],
                     seguranca.hash_senha(senha), secret, u["ativo"] == "True"))
                linhas_cred.append(f"{u['username']} | {senha} | {u['perfil']} | {secret}")
                exemplo.setdefault(u["perfil"], (u["username"], senha, secret))

            acessos = ler("registros_acesso.csv")
            with cur.copy("COPY registros_acesso (id, data_hora, cracha_uid, titular_id, "
                          "titular_nome, espaco, porta, resultado) FROM STDIN") as cp:
                for a in acessos:
                    tid = titular_por_uid.get(a["cracha_uid"], "")
                    cp.write_row((a["id"], a["data_hora"], a["cracha_uid"], tid,
                                  nomes.get(tid, ""), a["espaco"], a["porta"], a["resultado"]))

            for esp, disp, ini, fim in [("escola", "escola-bomba-01", "06:00", "08:00"),
                                        ("horta", "horta-reservatorio-01", "05:30", "07:00"),
                                        ("abrigo", "abrigo-reservatorio-01", "18:00", "20:00")]:
                cur.execute("INSERT INTO agendamentos_bomba (espaco, dispositivo, hora_inicio, hora_fim) "
                            "VALUES (%s,%s,%s,%s)", (esp, disp, ini, fim))

    SAIDA.mkdir(parents=True, exist_ok=True)
    (SAIDA / "credenciais.txt").write_text("\n".join(linhas_cred) + "\n", encoding="utf-8")
    print(f"Carga concluída: {len(usuarios)} operadores, {len(acessos)} registros de acesso, 3 agendamentos.")
    print("Exemplos por perfil (usuario / senha):")
    for perfil in ("operador", "tecnico", "coordenacao", "auditor"):
        if perfil in exemplo:
            print(f"  {perfil:12} {exemplo[perfil][0]} / {exemplo[perfil][1]}")
    print("Credenciais completas (com TOTP) em panel/out/credenciais.txt")


if __name__ == "__main__":
    main()
