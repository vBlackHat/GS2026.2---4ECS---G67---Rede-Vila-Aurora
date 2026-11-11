MODO = "vulneravel"
DB_USER = "painel_app"


def buscar_historico(cur, filtro, espaco):
    sql = (
        "SELECT id, data_hora, titular_nome, cracha_uid, espaco, porta, resultado "
        "FROM registros_acesso "
        "WHERE titular_nome ILIKE '%" + filtro + "%'"
    )
    if espaco:
        sql += " AND espaco = '" + espaco + "'"
    sql += " ORDER BY data_hora DESC LIMIT 200"
    cur.execute(sql)
    return cur.fetchall()


def autenticar(cur, username):
    cur.execute(
        "SELECT username, perfil, senha_hash, totp_secret, ativo "
        "FROM operadores_auth WHERE username = '" + username + "'"
    )
    return cur.fetchone()


def agendar_bomba(cur, agendamento_id, hora_inicio, hora_fim, usuario):
    cur.execute(
        "UPDATE agendamentos_bomba SET hora_inicio = '" + hora_inicio + "', "
        "hora_fim = '" + hora_fim + "', atualizado_em = now(), "
        "atualizado_por = '" + usuario + "' WHERE id = " + str(agendamento_id)
    )
    return cur.rowcount
