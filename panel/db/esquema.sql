CREATE TABLE IF NOT EXISTS operadores (
    username     TEXT PRIMARY KEY,
    nome         TEXT NOT NULL,
    email        TEXT NOT NULL,
    perfil       TEXT NOT NULL CHECK (perfil IN ('operador','tecnico','coordenacao','auditor')),
    senha_hash   TEXT NOT NULL,
    totp_secret  TEXT NOT NULL,
    ativo        BOOLEAN NOT NULL DEFAULT TRUE,
    criado_em    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS registros_acesso (
    id            BIGINT PRIMARY KEY,
    data_hora     TIMESTAMPTZ NOT NULL,
    cracha_uid    TEXT NOT NULL,
    titular_id    TEXT,
    titular_nome  TEXT,
    espaco        TEXT NOT NULL,
    porta         TEXT NOT NULL,
    resultado     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS registros_titular ON registros_acesso (titular_nome);

CREATE TABLE IF NOT EXISTS agendamentos_bomba (
    id             SERIAL PRIMARY KEY,
    espaco         TEXT NOT NULL,
    dispositivo    TEXT NOT NULL,
    hora_inicio    TEXT NOT NULL,
    hora_fim       TEXT NOT NULL,
    ativo          BOOLEAN NOT NULL DEFAULT TRUE,
    atualizado_em  TIMESTAMPTZ NOT NULL DEFAULT now(),
    atualizado_por TEXT NOT NULL DEFAULT 'carga'
);

CREATE TABLE IF NOT EXISTS auditoria (
    id       BIGSERIAL PRIMARY KEY,
    ts       TIMESTAMPTZ NOT NULL DEFAULT now(),
    usuario  TEXT,
    perfil   TEXT,
    acao     TEXT NOT NULL,
    detalhe  TEXT,
    ip       TEXT
);

CREATE OR REPLACE VIEW operadores_auth AS
    SELECT username, perfil, senha_hash, totp_secret, ativo FROM operadores;

CREATE OR REPLACE VIEW operadores_lista AS
    SELECT username, nome, email, perfil, ativo FROM operadores;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'painel_app') THEN CREATE ROLE painel_app LOGIN; END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'painel_ro') THEN CREATE ROLE painel_ro LOGIN; END IF;
END $$;

ALTER ROLE painel_app PASSWORD :'SENHA_APP';
ALTER ROLE painel_ro PASSWORD :'SENHA_RO';

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO painel_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO painel_app;

GRANT SELECT ON registros_acesso, agendamentos_bomba, operadores_auth, operadores_lista TO painel_ro;
GRANT UPDATE (hora_inicio, hora_fim, ativo, atualizado_em, atualizado_por) ON agendamentos_bomba TO painel_ro;
GRANT INSERT ON auditoria TO painel_ro;
GRANT USAGE, SELECT ON SEQUENCE auditoria_id_seq TO painel_ro;
