import json
import os
import socket
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psycopg

BIND = os.environ.get("BIND_ADDR", "10.99.0.1")
PORT = int(os.environ.get("PORT", "8443"))
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
CRL = os.environ.get("CRL", "/crl/crl.pem")
DSN = (f"host={os.environ.get('PGHOST', 'hub-postgres')} dbname={os.environ.get('PGDATABASE', 'vila')} "
       f"user={os.environ.get('PGUSER', 'vila_admin')} password={os.environ['PGPASSWORD']}")
SITES = {"ubs", "escola", "centro", "horta", "abrigo"}
TZ = timezone(timedelta(hours=-3))

SCHEMA = """
CREATE TABLE IF NOT EXISTS telemetria (
    device_id   TEXT NOT NULL,
    boot        BIGINT NOT NULL,
    seq         BIGINT NOT NULL,
    site        TEXT NOT NULL,
    tipo        TEXT,
    topico      TEXT NOT NULL,
    ts          TIMESTAMPTZ NOT NULL,
    recebido_em TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload     JSONB NOT NULL,
    PRIMARY KEY (device_id, boot, seq)
);
CREATE INDEX IF NOT EXISTS telemetria_site_ts ON telemetria (site, ts);
"""


def log(msg: str) -> None:
    print(f"{datetime.now(TZ).isoformat(timespec='seconds')} {msg}", flush=True)


def conectar_banco() -> psycopg.Connection:
    while True:
        try:
            conn = psycopg.connect(DSN, autocommit=True)
            conn.execute(SCHEMA)
            return conn
        except psycopg.OperationalError as exc:
            log(f"Banco indisponível ({exc.__class__.__name__}); nova tentativa em 3 s")
            time.sleep(3)


class Handler(BaseHTTPRequestHandler):
    conn: psycopg.Connection = None
    lock = threading.Lock()

    def log_message(self, fmt, *args):
        pass

    def _responder(self, codigo: int, corpo: dict) -> None:
        dados = json.dumps(corpo).encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(dados)))
        self.end_headers()
        self.wfile.write(dados)

    def do_POST(self):
        if self.path != "/ingest":
            return self._responder(404, {"erro": "não encontrado"})
        cert = self.connection.getpeercert() or {}
        cn = dict(x[0] for x in cert.get("subject", ())).get("commonName", "")
        try:
            corpo = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        except (ValueError, TypeError):
            return self._responder(400, {"erro": "JSON inválido"})
        site = corpo.get("site")
        if site not in SITES or cn != f"{site}-agent":
            log(f"RECUSADO: certificado '{cn}' tentou enviar dados como site '{site}' de {self.client_address[0]}")
            return self._responder(403, {"erro": "identidade não corresponde ao espaço"})
        eventos = corpo.get("eventos", [])
        novos = 0
        with Handler.lock, Handler.conn.transaction():
            for e in eventos:
                cur = Handler.conn.execute(
                    "INSERT INTO telemetria (device_id, boot, seq, site, tipo, topico, ts, payload) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (device_id, boot, seq) DO NOTHING",
                    (e["device_id"], int(e.get("boot", 0)), int(e["seq"]), site, e.get("tipo"), e["topico"], e["ts"],
                     json.dumps(e, ensure_ascii=False)))
                novos += cur.rowcount
        duplicados = len(eventos) - novos
        if len(eventos) > 50 or duplicados:
            log(f"{cn}: lote de {len(eventos)} eventos ({novos} novos, {duplicados} duplicados ignorados)")
        self._responder(200, {"recebidos": len(eventos), "novos": novos, "duplicados": duplicados})


def contexto_tls() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(f"{CERT_DIR}/hub-ingest.crt", f"{CERT_DIR}/hub-ingest.key")
    ctx.load_verify_locations(f"{CERT_DIR}/ca-chain.crt")
    ctx.load_verify_locations(CRL)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    return ctx


def aguardar_tunel() -> None:
    while True:
        try:
            s = socket.socket()
            s.bind((BIND, 0))
            s.close()
            return
        except OSError:
            log(f"Aguardando a interface do túnel ({BIND})")
            time.sleep(2)


def main() -> None:
    Handler.conn = conectar_banco()
    aguardar_tunel()
    servidor = ThreadingHTTPServer((BIND, PORT), Handler)
    servidor.socket = contexto_tls().wrap_socket(servidor.socket, server_side=True)
    log(f"Ingestão ouvindo SOMENTE no túnel: https://{BIND}:{PORT}/ingest (mTLS + CRL)")
    servidor.serve_forever()


if __name__ == "__main__":
    main()
