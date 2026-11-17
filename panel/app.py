import importlib
import os
from datetime import datetime, timezone, timedelta
from functools import wraps

import psycopg
from flask import Flask, request, session, redirect, url_for, render_template, abort, flash

import seguranca

MODO = os.environ.get("PAINEL_MODO", "corrigido")
consultas = importlib.import_module(f"consultas_{MODO}")
TZ = timezone(timedelta(hours=-3))
MFA_ATIVO = MODO == "corrigido"
RBAC_ATIVO = MODO == "corrigido"
ERRO_DETALHADO = MODO == "vulneravel"

PERMISSOES = {
    "historico": {"operador", "tecnico", "coordenacao", "auditor"},
    "bomba_ver": {"operador", "tecnico", "coordenacao", "auditor"},
    "bomba_alterar": {"tecnico", "coordenacao"},
    "usuarios": {"coordenacao"},
    "auditoria": {"auditor", "coordenacao"},
}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "lab-vila-aurora")


def conectar():
    return psycopg.connect(
        host=os.environ.get("PGHOST", "hub-postgres"),
        dbname=os.environ.get("PGDATABASE", "painel"),
        user=os.environ.get("PGUSER", consultas.DB_USER),
        password=os.environ["PGPASSWORD"], autocommit=True)


def auditar(usuario, perfil, acao, detalhe):
    try:
        with conectar() as c:
            c.execute("INSERT INTO auditoria (usuario, perfil, acao, detalhe, ip) "
                      "VALUES (%s,%s,%s,%s,%s)", (usuario, perfil, acao, detalhe,
                      request.headers.get("X-Forwarded-For", request.remote_addr)))
    except psycopg.Error:
        pass


def logado(f):
    @wraps(f)
    def wrap(*a, **k):
        if not session.get("auth"):
            return redirect(url_for("login"))
        if MFA_ATIVO and not session.get("mfa_ok"):
            return redirect(url_for("mfa"))
        return f(*a, **k)
    return wrap


def exige(acao):
    def deco(f):
        @wraps(f)
        def wrap(*a, **k):
            if RBAC_ATIVO and session.get("perfil") not in PERMISSOES[acao]:
                auditar(session.get("user"), session.get("perfil"), "acesso_negado", acao)
                abort(403)
            return f(*a, **k)
        return wrap
    return deco


@app.route("/healthz")
def healthz():
    return {"modo": MODO, "ok": True}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario", "")
        senha = request.form.get("senha", "")
        try:
            with conectar() as c, c.cursor() as cur:
                linha = consultas.autenticar(cur, usuario)
        except Exception as exc:
            return render_template("login.html", erro=_erro(exc)), 500
        if linha and linha[4] and seguranca.conferir_senha(senha, linha[2]):
            session.clear()
            session.update(auth=True, user=linha[0], perfil=linha[1], mfa_ok=not MFA_ATIVO)
            auditar(linha[0], linha[1], "login_ok", f"modo={MODO}")
            return redirect(url_for("mfa") if MFA_ATIVO else url_for("inicio"))
        auditar(usuario, None, "login_falha", "")
        return render_template("login.html", erro="Usuário ou senha inválidos.")
    return render_template("login.html")


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    if not session.get("auth"):
        return redirect(url_for("login"))
    if not MFA_ATIVO:
        return redirect(url_for("inicio"))
    if request.method == "POST":
        # O segredo TOTP fica só no banco: o cookie de sessão é assinado, mas não cifrado.
        try:
            with conectar() as c, c.cursor() as cur:
                linha = consultas.autenticar(cur, session.get("user", ""))
        except Exception as exc:
            return render_template("mfa.html", erro=_erro(exc)), 500
        segredo = linha[3] if linha and linha[4] else ""
        if segredo and seguranca.conferir_totp(segredo, request.form.get("codigo", "")):
            session["mfa_ok"] = True
            auditar(session.get("user"), session.get("perfil"), "mfa_ok", "")
            return redirect(url_for("inicio"))
        auditar(session.get("user"), session.get("perfil"), "mfa_falha", "")
        return render_template("mfa.html", erro="Código inválido.")
    return render_template("mfa.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@logado
def inicio():
    return render_template("inicio.html", perfil=session.get("perfil"),
                           user=session.get("user"), modo=MODO, permissoes=PERMISSOES)


@app.route("/historico")
@logado
@exige("historico")
def historico():
    filtro = request.args.get("q", "")
    espaco = request.args.get("espaco", "")
    linhas, erro = [], None
    if "q" in request.args:
        try:
            with conectar() as c, c.cursor() as cur:
                linhas = consultas.buscar_historico(cur, filtro, espaco)
            auditar(session.get("user"), session.get("perfil"), "busca_historico", filtro)
        except Exception as exc:
            erro = _erro(exc)
    return render_template("historico.html", linhas=linhas, q=filtro, espaco=espaco, erro=erro)


@app.route("/bomba", methods=["GET", "POST"])
@logado
def bomba():
    if request.method == "POST":
        if RBAC_ATIVO and session.get("perfil") not in PERMISSOES["bomba_alterar"]:
            auditar(session.get("user"), session.get("perfil"), "acesso_negado", "bomba_alterar")
            abort(403)
        try:
            with conectar() as c, c.cursor() as cur:
                n = consultas.agendar_bomba(cur, request.form.get("id"),
                        request.form.get("inicio", ""), request.form.get("fim", ""),
                        session.get("user"))
            auditar(session.get("user"), session.get("perfil"), "altera_agendamento",
                    f"id={request.form.get('id')} {request.form.get('inicio')}-{request.form.get('fim')}")
            flash(f"{n} agendamento(s) atualizado(s).")
        except Exception as exc:
            flash("Erro ao atualizar: " + _erro(exc))
        return redirect(url_for("bomba"))
    with conectar() as c, c.cursor() as cur:
        cur.execute("SELECT id, espaco, dispositivo, hora_inicio, hora_fim, ativo, "
                    "atualizado_em, atualizado_por FROM agendamentos_bomba ORDER BY id")
        ags = cur.fetchall()
    pode = not RBAC_ATIVO or session.get("perfil") in PERMISSOES["bomba_alterar"]
    return render_template("bomba.html", agendamentos=ags, pode_alterar=pode)


@app.route("/usuarios")
@logado
@exige("usuarios")
def usuarios():
    with conectar() as c, c.cursor() as cur:
        cur.execute("SELECT username, nome, email, perfil, ativo FROM operadores_lista ORDER BY perfil, username")
        lista = cur.fetchall()
    return render_template("usuarios.html", usuarios=lista)


def _erro(exc):
    return str(exc) if ERRO_DETALHADO else "Ocorreu um erro ao processar a solicitação."


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
