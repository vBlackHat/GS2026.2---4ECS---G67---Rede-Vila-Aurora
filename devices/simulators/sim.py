import csv
import json
import math
import os
import random
import threading
import time
from datetime import datetime, timedelta, timezone

import paho.mqtt.client as mqtt

SITE = os.environ["SITE"]
MQTT_HOST = os.environ.get("MQTT_HOST", "broker")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "8883"))
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
INVENTARIO = os.environ.get("INVENTARIO", "/app/inventory.json")
INTERVALO = float(os.environ.get("SIM_INTERVAL", "5"))
CRACHAS_CSV = os.environ.get("CRACHAS_CSV", "/dados/crachas.csv")
TZ = timezone(timedelta(hours=-3))
BOOT = int(time.time())


def agora() -> datetime:
    return datetime.now(TZ)


class Dispositivo(threading.Thread):
    tipo = "generico"

    def __init__(self, device_id: str):
        super().__init__(daemon=True)
        self.device_id = device_id
        self.base = f"vila/{SITE}/{device_id}"
        self.seq = 0
        self.cenario: str | None = None
        self.rnd = random.Random(device_id)
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=device_id)
        self.client.on_connect = self._on_connect
        self.client.on_connect_fail = self._on_connect_fail
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message
        self.client.tls_set(
            ca_certs=f"{CERT_DIR}/ca-chain.crt",
            certfile=f"{CERT_DIR}/{device_id}.crt",
            keyfile=f"{CERT_DIR}/{device_id}.key",
        )
        self.client.reconnect_delay_set(min_delay=1, max_delay=30)

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        print(f"[{self.device_id}] conectado ao broker ({reason_code})", flush=True)
        client.subscribe(f"{self.base}/comando", qos=1)
        client.subscribe(f"vila/{SITE}/sim/cenario", qos=1)

    def _on_connect_fail(self, client, userdata):
        print(f"[{self.device_id}] conexão recusada pelo broker (TLS/certificado)", flush=True)

    def _on_disconnect(self, client, userdata, flags, reason_code, properties):
        print(f"[{self.device_id}] desconectado ({reason_code})", flush=True)

    def _on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return
        if msg.topic.endswith("/sim/cenario"):
            if payload.get("alvo") in (None, self.device_id):
                self.cenario = payload.get("tipo")
                print(f"[{self.device_id}] cenário: {self.cenario or 'normal'}", flush=True)
        else:
            self.comando(payload)

    def comando(self, payload: dict) -> None:
        pass

    def publicar(self, sufixo: str, dados: dict) -> None:
        self.seq += 1
        msg = {
            "device_id": self.device_id,
            "site": SITE,
            "tipo": self.tipo,
            "ts": agora().isoformat(timespec="milliseconds"),
            "boot": BOOT,
            "seq": self.seq,
            **dados,
        }
        self.client.publish(f"{self.base}/{sufixo}", json.dumps(msg, ensure_ascii=False), qos=1)

    def passo(self) -> None:
        raise NotImplementedError

    def run(self) -> None:
        self.client.connect_async(MQTT_HOST, MQTT_PORT, keepalive=30)
        self.client.loop_start()
        time.sleep(self.rnd.uniform(0, INTERVALO))
        while True:
            try:
                self.passo()
            except Exception as exc:
                print(f"[{self.device_id}] erro: {exc}", flush=True)
            time.sleep(INTERVALO * self.rnd.uniform(0.9, 1.1))


class CamaraFria(Dispositivo):
    tipo = "camara_fria"

    def __init__(self, device_id: str):
        super().__init__(device_id)
        self.temp = 5.0

    def passo(self) -> None:
        if self.cenario == "falha_refrigeracao":
            self.temp = min(25.0, self.temp + self.rnd.uniform(0.3, 0.6))
        else:
            self.temp += (5.0 - self.temp) * 0.2 + self.rnd.gauss(0, 0.15)
        self.publicar("telemetria", {
            "temperatura_c": round(self.temp, 2),
            "porta_aberta": self.rnd.random() < 0.03,
        })


class Energia(Dispositivo):
    tipo = "energia"

    def __init__(self, device_id: str, com_gerador: bool = False):
        super().__init__(device_id)
        self.bateria = 80.0
        self.com_gerador = com_gerador
        self.gerador = False

    def passo(self) -> None:
        h = agora().hour + agora().minute / 60
        solar = max(0.0, math.sin((h - 6) / 12 * math.pi)) * 3.5 * self.rnd.uniform(0.85, 1.0)
        consumo = self.rnd.uniform(1.0, 2.2)
        if self.cenario == "pico_consumo":
            consumo *= 3
        self.bateria = max(0.0, min(100.0, self.bateria + (solar - consumo) * 0.3))
        if self.com_gerador:
            self.gerador = self.bateria < 20 or (self.gerador and self.bateria < 40)
            if self.gerador:
                self.bateria = min(100.0, self.bateria + 1.5)
        dados = {
            "solar_kw": round(solar, 2),
            "consumo_kw": round(consumo, 2),
            "bateria_pct": round(self.bateria, 1),
        }
        if self.com_gerador:
            dados["gerador_ligado"] = self.gerador
        self.publicar("telemetria", dados)


class Bomba(Dispositivo):
    tipo = "bomba"

    def __init__(self, device_id: str):
        super().__init__(device_id)
        self.ligada = False
        self.modo = "auto"

    def comando(self, payload: dict) -> None:
        acao = payload.get("acao")
        if self.cenario == "bomba_travada":
            self.publicar("evento", {"evento": "comando_ignorado", "acao": acao, "motivo": "falha mecanica simulada"})
            return
        if acao == "ligar":
            self.ligada = True
        elif acao == "desligar":
            self.ligada = False
        elif acao == "modo_seguro":
            self.ligada, self.modo = False, "seguro"
        elif acao == "modo_auto":
            self.modo = "auto"
        else:
            return
        self.publicar("evento", {"evento": "comando_executado", "acao": acao, "origem": payload.get("origem", "desconhecida")})

    def passo(self) -> None:
        if self.cenario == "bomba_travada":
            self.ligada = True
        self.publicar("estado", {"ligada": self.ligada, "modo": self.modo})


class Reservatorio(Dispositivo):
    tipo = "reservatorio"

    def __init__(self, device_id: str, bomba: Bomba | None = None):
        super().__init__(device_id)
        self.nivel = 70.0
        self.bomba = bomba

    def passo(self) -> None:
        h = agora().hour
        consumo = self.rnd.uniform(0.4, 1.0) if 6 <= h < 19 else self.rnd.uniform(0.0, 0.15)
        if self.cenario == "vazamento":
            consumo += 2.0
        enchimento = 1.5 if self.bomba and self.bomba.ligada else 0.0
        self.nivel = max(0.0, min(100.0, self.nivel - consumo + enchimento))
        if self.bomba and self.bomba.modo == "auto" and self.cenario != "bomba_travada":
            if self.nivel < 30 and not self.bomba.ligada:
                self.bomba.comando({"acao": "ligar", "origem": "controle_local_simulado"})
            elif self.nivel > 90 and self.bomba.ligada:
                self.bomba.comando({"acao": "desligar", "origem": "controle_local_simulado"})
        self.publicar("telemetria", {
            "nivel_pct": round(self.nivel, 1),
            "turbidez_ntu": round(abs(self.rnd.gauss(0.6, 0.2)), 2),
            "cloro_residual_mg_l": round(max(0.0, self.rnd.gauss(1.0, 0.15)), 2),
        })


class QualidadeAr(Dispositivo):
    tipo = "qualidade_ar"

    def passo(self) -> None:
        self.publicar("telemetria", {
            "umidade_pct": round(self.rnd.uniform(45, 70), 1),
            "co2_ppm": int(self.rnd.gauss(650, 80)),
            "temperatura_ambiente_c": round(self.rnd.gauss(24, 1.5), 1),
        })


class Alagamento(Dispositivo):
    tipo = "alagamento"

    def __init__(self, device_id: str):
        super().__init__(device_id)
        self.nivel_cm = 0.0

    def passo(self) -> None:
        if self.cenario == "chuva_forte":
            self.nivel_cm += self.rnd.uniform(0.5, 1.5)
        else:
            self.nivel_cm = max(0.0, self.nivel_cm - 0.5)
        self.publicar("telemetria", {"nivel_agua_cm": round(self.nivel_cm, 1)})


class Fechadura(Dispositivo):
    tipo = "fechadura"

    def __init__(self, device_id: str, porta: str):
        super().__init__(device_id)
        self.porta = porta
        self.travada = True
        self.autorizados, self.outros = self._carregar_crachas()

    def _carregar_crachas(self) -> tuple[list[str], list[str]]:
        autorizados, outros = [], []
        try:
            with open(CRACHAS_CSV, encoding="utf-8") as f:
                for linha in csv.DictReader(f):
                    destino = autorizados if SITE in linha["espacos_autorizados"].split(";") else outros
                    destino.append(linha["uid"])
        except FileNotFoundError:
            print(f"[{self.device_id}] crachas.csv não encontrado; sem eventos de acesso", flush=True)
        return autorizados, outros

    def comando(self, payload: dict) -> None:
        acao = payload.get("acao")
        if acao in ("liberar", "travar"):
            self.travada = acao == "travar"
            self.publicar("evento", {"evento": "comando_executado", "acao": acao, "origem": payload.get("origem", "desconhecida")})

    def passo(self) -> None:
        if self.autorizados and self.rnd.random() < 0.2:
            negado = self.outros and self.rnd.random() < 0.05
            uid = self.rnd.choice(self.outros if negado else self.autorizados)
            self.publicar("evento", {
                "evento": "leitura_cracha",
                "porta": self.porta,
                "cracha_uid": uid,
                "resultado": "negado" if negado else "liberado",
            })
        self.publicar("estado", {"porta": self.porta, "travada": self.travada})


def montar_dispositivos() -> list[Dispositivo]:
    with open(INVENTARIO, encoding="utf-8") as f:
        itens = json.load(f)[SITE]
    simples = {"camara_fria": CamaraFria, "qualidade_ar": QualidadeAr, "alagamento": Alagamento, "bomba": Bomba}
    criados: dict[str, Dispositivo] = {}
    for item in sorted(itens, key=lambda i: i["tipo"] != "bomba"):
        did, tipo = item["id"], item["tipo"]
        if tipo == "energia":
            criados[did] = Energia(did, com_gerador=item.get("gerador", False))
        elif tipo == "fechadura":
            criados[did] = Fechadura(did, item["porta"])
        elif tipo == "reservatorio":
            criados[did] = Reservatorio(did, criados.get(item.get("bomba")))
        else:
            criados[did] = simples[tipo](did)
    return [criados[i["id"]] for i in itens]


def main() -> None:
    dispositivos = montar_dispositivos()
    print(f"Simulador {SITE} (boot {BOOT}): {', '.join(d.device_id for d in dispositivos)}", flush=True)
    for d in dispositivos:
        d.start()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
