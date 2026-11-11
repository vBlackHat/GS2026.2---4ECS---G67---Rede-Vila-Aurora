import re

MODO = "corrigido"
DB_USER = "painel_ro"

HORA = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def buscar_historico(cur, filtro, espaco):
    if len(filtro) > 80 or (espaco and espaco not in
                            {"ubs", "escola", "centro", "horta", "abrigo"}):
        raise ValueError("parâmetro de busca inválido")
    sql = ("SELECT id, data_hora, titular_nome, cracha_uid, espaco, porta, resultado "
           "FROM registros_acesso WHERE titular_nome ILIKE %s")
    params = [f"%{filtro}%"]
    if espaco:
        sql += " AND espaco = %s"
        params.append(espaco)
    sql += " ORDER BY data_hora DESC LIMIT 200"
    cur.execute(sql, params)
    return cur.fetchall()


def autenticar(cur, username):
    if not re.fullmatch(r"[a-z0-9._-]{1,40}", username or ""):
        return None
    cur.execute(
        "SELECT username, perfil, senha_hash, totp_secret, ativo "
        "FROM operadores_auth WHERE username = %s", (username,))
    return cur.fetchone()


def agendar_bomba(cur, agendamento_id, hora_inicio, hora_fim, usuario):
    if not (HORA.match(hora_inicio) and HORA.match(hora_fim)):
        raise ValueError("horário inválido (use HH:MM)")
    cur.execute(
        "UPDATE agendamentos_bomba SET hora_inicio = %s, hora_fim = %s, "
        "atualizado_em = now(), atualizado_por = %s WHERE id = %s",
        (hora_inicio, hora_fim, usuario, int(agendamento_id)))
    return cur.rowcount
