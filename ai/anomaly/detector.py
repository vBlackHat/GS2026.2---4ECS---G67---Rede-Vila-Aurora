import json
import os

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler

CSV = os.environ.get("CSV", "/dados/telemetria.csv")
SAIDA = os.environ.get("SAIDA", "/saida")
SEMENTE = 2026

# Por tipo de sensor: features usadas e a regra física de verdade-terrestre (mesma lógica do alarme da borda, B08)
SPEC = {
    "camara_fria":  (["temperatura_c"],
                     lambda r: (r.get("temperatura_c", 5) > 8) or (r.get("temperatura_c", 5) < 2)),
    "energia":      (["bateria_pct", "consumo_kw", "solar_kw"],
                     lambda r: (r.get("bateria_pct", 100) < 15) or (r.get("consumo_kw", 0) > 4.5)),
    "reservatorio": (["nivel_pct", "turbidez_ntu", "cloro_residual_mg_l"],
                     lambda r: (r.get("nivel_pct", 70) < 15) or (r.get("nivel_pct", 70) > 98)
                     or (r.get("turbidez_ntu", 0) > 2.0)),
    "alagamento":   (["nivel_agua_cm"],
                     lambda r: r.get("nivel_agua_cm", 0) > 10),
}


def carregar() -> pd.DataFrame:
    df = pd.read_csv(CSV)
    df["payload"] = df["payload"].apply(lambda x: x if isinstance(x, dict) else json.loads(x))
    return df


def avaliar() -> list[str]:
    df = carregar()
    linhas = [f"Detecção de anomalias com Isolation Forest (semente {SEMENTE}).",
              f"Total de leituras de telemetria: {len(df)}",
              f"{'tipo':<13} {'leituras':>8} {'anom_reais':>10} {'precisao':>9} {'revocacao':>10} "
              f"{'f1':>6} {'falsos_pos':>11}"]
    tp = fp = fn = tn = 0
    for tipo, (feats, rotulo) in SPEC.items():
        sub = df[df["tipo"] == tipo].copy()
        if sub.empty:
            continue
        X = pd.DataFrame([{f: p.get(f, np.nan) for f in feats} for p in sub["payload"]]).fillna(0.0)
        y = np.array([1 if rotulo(p) else 0 for p in sub["payload"]])
        taxa = float(np.clip(y.mean() if y.mean() > 0 else 0.03, 0.02, 0.25))
        Xs = StandardScaler().fit_transform(X.values)
        clf = IsolationForest(contamination=taxa, random_state=SEMENTE, n_estimators=200)
        yhat = (clf.fit_predict(Xs) == -1).astype(int)
        p = precision_score(y, yhat, zero_division=0)
        r = recall_score(y, yhat, zero_division=0)
        f1 = f1_score(y, yhat, zero_division=0)
        cm = confusion_matrix(y, yhat, labels=[0, 1])
        tn_, fp_, fn_, tp_ = cm.ravel() if cm.size == 4 else (len(y), 0, 0, 0)
        tp += tp_; fp += fp_; fn += fn_; tn += tn_
        linhas.append(f"{tipo:<13} {len(sub):>8} {int(y.sum()):>10} {p:>9.2f} {r:>10.2f} {f1:>6.2f} {fp_:>11}")
    pg = tp / (tp + fp) if tp + fp else 0
    rg = tp / (tp + fn) if tp + fn else 0
    f1g = 2 * pg * rg / (pg + rg) if pg + rg else 0
    linhas.append(f"{'GLOBAL':<13} {tp + fp + fn + tn:>8} {tp + fn:>10} {pg:>9.2f} {rg:>10.2f} {f1g:>6.2f} {fp:>11}")
    linhas.append(f"Matriz global: VP={tp} FP={fp} FN={fn} VN={tn}")
    os.makedirs(SAIDA, exist_ok=True)
    (open(os.path.join(SAIDA, "metricas_anomalia.txt"), "w", encoding="utf-8")
     .write("\n".join(linhas) + "\n"))
    return linhas


if __name__ == "__main__":
    print("\n".join(avaliar()))
