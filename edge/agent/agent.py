import json
import os
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import paho.mqtt.client as mqtt

SITE = os.environ["SITE"]
AGENTE = f"{SITE}-agent"
MQTT_HOST = os.environ.get("MQTT_HOST", "broker")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "8883"))
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
INGEST_URL = os.environ.get("INGEST_URL", "https://10.99.0.1:8443/ingest")
DB_PATH = os.environ.get("DB_PATH", "/data/outbox.sqlite")
STATUS_PATH = os.environ.get("STATUS_PATH", "/data/status.json")
INTERVALO_ENVIO = float(os.environ.get("INTERVALO_ENVIO", "5"))
LOTE = int(os.environ.get("LOTE", "500"))
TZ = timezone(timedelta(hours=-3))

CA = f"{CERT_DIR}/ca-chain.crt"
CERT = f"{CERT_DIR}/{AGENTE}.crt"
KEY = f"{CERT_DIR}/{AGENTE}.key"


def agora() -> str:
    return datetime.now(TZ).isoformat(timespec="milliseconds")


def log(msg: str) -> None:
    print(f"{agora()} {msg}", flush=True)


class Fila:
    def __init__(self, caminho: str):
        os.makedirs(os.path.dirname(caminho), exist_ok=True)
        self.db = sqlite3.connect(caminho, check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                boot INTEGER NOT NULL,
                seq INTEGER NOT NULL,
                topico TEXT NOT NULL,
                ts TEXT NOT NULL,
                payload TEXT NOT NULL,
                enviado INTEGER NOT NULL DEFAULT 0,
                UNIQUE (device_id, boot, seq)
            )""")
        self.db.execute("CREATE TABLE IF NOT EXISTS meta (chave TEXT PRIMARY KEY, valor TEXT)")
        self.lock = threading.Lock()
        linha = self.db.execute("SELECT valor FROM meta WHERE chave = 'boot_agente'").fetchone()
        if linha:
            self.boot = int(linha[0])
        else:
            self.boot = int(time.time())
            self.db.execute("INSERT INTO meta VALUES ('boot_agente', ?)", (str(self.boot),))

    def guardar(self, device_id: str, boot: int, seq: int, topico: str, ts: str, payload: str) -> str:
        with self.lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO outbox (device_id, boot, seq, topico, ts, payload) VALUES (?,?,?,?,?,?)",
                (device_id, boot, seq, topico, ts, payload))
            if cur.rowcount == 1:
                return "novo"
            anterior = self.db.execute(
                "SELECT payload FROM outbox WHERE device_id = ? AND boot = ? AND seq = ?",
                (device_id, boot, seq)).fetchone()
            return "duplicado" if anterior and anterior[0] == payload else "conflito"

    def pendentes(self, limite: int) -> list[tuple]:
        with self.lock:
            return self.db.execute(
                "SELECT id, payload, topico FROM outbox WHERE enviado = 0 ORDER BY id LIMIT ?", (limite,)).fetchall()

    def marcar_enviados(self, ids: list[int]) -> None:
        with self.lock:
            self.db.executemany("UPDATE outbox SET enviado = 1 WHERE id = ?", [(i,) for i in ids])

    def contagem(self) -> tuple[int, int]:
        with self.lock:
            total, pend = self.db.execute(
                "SELECT COUNT(*), COALESCE(SUM(enviado = 0), 0) FROM outbox").fetchone()
            return total, pend

    def proximo_seq(self) -> int:
        with self.lock:
            linha = self.db.execute("SELECT valor FROM meta WHERE chave = 'seq_agente'").fetchone()
            seq = int(linha[0]) + 1 if linha else 1
            self.db.execute("INSERT OR REPLACE INTO meta VALUES ('seq_agente', ?)", (str(seq),))
            return seq


class Regras:
    def __init__(self):
        self.ativos: dict[str, bool] = {}

    def avaliar(self, msg: dict) -> list[tuple[str, str, bool, str]]:
        tipo, dev = msg.get("tipo"), msg.get("device_id")
        verificacoes = []
        if tipo == "camara_fria" and "temperatura_c" in msg:
            t = msg["temperatura_c"]
            verificacoes.append(("camara_fria_fora_da_faixa", "critica", t > 8.0 or t < 2.0,
                                 f"temperatura {t} °C (faixa segura 2-8 °C)"))
        if tipo == "reservatorio" and "nivel_pct" in msg:
            n = msg["nivel_pct"]
            verificacoes.append(("reservatorio_baixo", "alta", n < 15, f"nível {n}%"))
            verificacoes.append(("reservatorio_transbordando", "media", n > 98, f"nível {n}%"))
        if tipo == "alagamento" and "nivel_agua_cm" in msg:
            a = msg["nivel_agua_cm"]
            verificacoes.append(("alagamento", "critica", a > 10, f"lâmina d'água {a} cm"))
        if tipo == "energia" and "bateria_pct" in msg:
            b = msg["bateria_pct"]
            verificacoes.append(("bateria_baixa", "alta", b < 15, f"bateria {b}%"))
        if tipo == "bomba" and "ligada" in msg:
            hora = datetime.now(TZ).hour
            fora = msg["ligada"] and (hora >= 22 or hora < 5)
            verificacoes.append(("bomba_ligada_fora_do_horario", "alta", fora, f"bomba ligada às {hora}h"))

        mudancas = []
        for regra, sev, ativo, detalhe in verificacoes:
            chave = f"{dev}:{regra}"
            if ativo != self.ativos.get(chave, False):
                self.ativos[chave] = ativo
                mudancas.append((regra, sev, ativo, detalhe))
        return mudancas


class Agente:
    def __init__(self):
        self.fila = Fila(DB_PATH)
        self.regras = Regras()
        self.online = None
        self.ultimo_envio_ok = None
        self.reenviados_total = 0
        self.alarmes_ativos: dict[str, dict] = {}
        self.ultima_msg = time.time()
        self.mqtt_conectado = False
        self.ultimo_alerta_seq: dict[str, float] = {}
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=AGENTE)
        self.client.tls_set(ca_certs=CA, certfile=CERT, keyfile=KEY)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect
        self.client.reconnect_delay_set(min_delay=1, max_delay=30)
        self.ssl_ctx = ssl.create_default_context(cafile=CA)
        self.ssl_ctx.load_cert_chain(CERT, KEY)

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        log(f"MQTT: conectado ao broker local ({reason_code})")
        self.mqtt_conectado = True
        self.ultima_msg = time.time()
        for t in ("telemetria", "estado", "evento"):
            client.subscribe(f"vila/{SITE}/+/{t}", qos=1)

    def _on_disconnect(self, client, userdata, flags, reason_code, properties):
        self.mqtt_conectado = False
        log(f"MQTT: desconectado do broker local ({reason_code}); reconexão automática")

    def _on_message(self, client, userdata, msg):
        self.ultima_msg = time.time()
        try:
            dados = json.loads(msg.payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return
        if "device_id" not in dados or "seq" not in dados:
            return
        boot, seq = int(dados.get("boot", 0)), int(dados["seq"])
        resultado = self.fila.guardar(dados["device_id"], boot, seq, msg.topic,
                                      dados.get("ts", agora()), msg.payload.decode("utf-8"))
        if resultado == "conflito":
            self._alerta_seq(dados["device_id"], boot, seq, msg.topic)
        if resultado != "novo":
            return
        for regra, sev, ativo, detalhe in self.regras.avaliar(dados):
            self._alarme(dados["device_id"], regra, sev, ativo, detalhe)

    def _evento_agente(self, tipo: str, topico: str, campos: dict) -> dict:
        evento = {
            "device_id": AGENTE,
            "site": SITE,
            "tipo": tipo,
            "ts": agora(),
            "boot": self.fila.boot,
            "seq": self.fila.proximo_seq(),
            **campos,
        }
        self.fila.guardar(AGENTE, evento["boot"], evento["seq"], topico, evento["ts"],
                          json.dumps(evento, ensure_ascii=False))
        return evento

    def _alerta_seq(self, device_id: str, boot: int, seq: int, topico: str) -> None:
        agora_s = time.time()
        if agora_s - self.ultimo_alerta_seq.get(device_id, 0) < 60:
            return
        self.ultimo_alerta_seq[device_id] = agora_s
        self._evento_agente("alerta_seguranca", f"vila/{SITE}/agent/alerta", {
            "regra": "seq_repetido_conteudo_diferente",
            "severidade": "alta",
            "origem": device_id,
            "boot_origem": boot,
            "seq_origem": seq,
            "topico_origem": topico,
            "detalhe": "mensagem com identificador já recebido e conteúdo diferente: possível clone, replay ou contador reiniciado",
        })
        log(f"ALERTA DE SEGURANÇA: seq repetido com conteúdo diferente em {device_id} "
            f"(boot {boot}, seq {seq}); possível clone, replay ou contador reiniciado")

    def _alarme(self, device_id: str, regra: str, sev: str, ativo: bool, detalhe: str) -> None:
        estado = "ATIVADO" if ativo else "normalizado"
        topico = f"vila/{SITE}/agent/alarme"
        evento = self._evento_agente("alarme_local", topico, {
            "origem": device_id,
            "regra": regra,
            "severidade": sev,
            "ativo": ativo,
            "detalhe": detalhe,
            "decidido_em": "borda",
            "hub_alcancavel": bool(self.online),
        })
        chave = f"{device_id}:{regra}"
        if ativo:
            self.alarmes_ativos[chave] = evento
        else:
            self.alarmes_ativos.pop(chave, None)
        self.client.publish(topico, json.dumps(evento, ensure_ascii=False), qos=1, retain=True)
        log(f"ALARME LOCAL {estado}: {regra} [{sev}] em {device_id}: {detalhe} "
            f"(decidido na borda; hub {'alcançável' if self.online else 'INACESSÍVEL'})")
        if ativo and sev == "critica":
            log(f"AVISO 4G (simulado): SMS para a coordenação: {regra} em {device_id}")

    def _enviar_lote(self) -> int:
        pend = self.fila.pendentes(LOTE)
        corpo = json.dumps({
            "site": SITE,
            "agente": AGENTE,
            "eventos": [{"topico": t, **json.loads(p)} for _, p, t in pend],
        }).encode("utf-8")
        req = urllib.request.Request(INGEST_URL, data=corpo, method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, context=self.ssl_ctx, timeout=10) as resp:
            if resp.status != 200:
                raise urllib.error.HTTPError(INGEST_URL, resp.status, "falha", resp.headers, None)
        if pend:
            self.fila.marcar_enviados([i for i, _, _ in pend])
        return len(pend)

    def _encaminhador(self) -> None:
        while True:
            try:
                enviados = 0
                while True:
                    n = self._enviar_lote()
                    enviados += n
                    if n < LOTE:
                        break
                if self.online is not True:
                    total, pend = self.fila.contagem()
                    log(f"LINK HUB: online; {enviados} eventos enviados da fila (pendentes agora: {pend})")
                    self.reenviados_total += enviados
                self.online = True
                self.ultimo_envio_ok = agora()
            except Exception as exc:
                if self.online is not False:
                    _, pend = self.fila.contagem()
                    log(f"LINK HUB: OFFLINE ({type(exc).__name__}); operando localmente, fila com {pend} pendentes")
                self.online = False
            self._status()
            time.sleep(INTERVALO_ENVIO)

    def _vigia(self) -> None:
        while True:
            time.sleep(10)
            silencio = time.time() - self.ultima_msg
            if self.mqtt_conectado and silencio > 30:
                log(f"MQTT: nenhuma mensagem dos sensores há {int(silencio)} s; forçando reconexão ao broker")
                self.ultima_msg = time.time()
                try:
                    self.client.reconnect()
                except Exception as exc:
                    log(f"MQTT: falha ao reconectar ({type(exc).__name__}); nova tentativa automática")

    def _status(self) -> None:
        total, pend = self.fila.contagem()
        status = {
            "site": SITE,
            "atualizado_em": agora(),
            "hub_online": self.online,
            "mqtt_conectado": self.mqtt_conectado,
            "segundos_desde_ultima_msg": int(time.time() - self.ultima_msg),
            "ultimo_envio_ok": self.ultimo_envio_ok,
            "fila_total": total,
            "fila_pendente": pend,
            "alarmes_ativos": list(self.alarmes_ativos.values()),
        }
        tmp = STATUS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(status, f, ensure_ascii=False, indent=2)
        os.replace(tmp, STATUS_PATH)

    def rodar(self) -> None:
        log(f"Agente de borda {AGENTE} iniciado; fila em {DB_PATH}; hub em {INGEST_URL}")
        self.client.connect_async(MQTT_HOST, MQTT_PORT, keepalive=30)
        self.client.loop_start()
        threading.Thread(target=self._encaminhador, daemon=True).start()
        threading.Thread(target=self._vigia, daemon=True).start()
        while True:
            time.sleep(3600)


if __name__ == "__main__":
    Agente().rodar()
