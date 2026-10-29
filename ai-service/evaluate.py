"""
Avaliação reproduzível do detector (dados SINTÉTICOS de train.py, semente fixa).

Uso: python evaluate.py
Mede falso positivo (tráfego normal com score acima do limiar) e detecção
(ataques acima do limiar). Os números valem para o gerador sintético e NÃO
substituem uma avaliação com tráfego real.
"""

import contextlib
import io
import warnings

import numpy as np

warnings.filterwarnings("ignore")

from model import AnomalyDetectorV2  # noqa: E402
import train  # noqa: E402

np.random.seed(123)
with contextlib.redirect_stdout(io.StringIO()):
    normal = train.generate_normal_traffic(500)
    attack = train.generate_anomalous_traffic(500)
    detector = AnomalyDetectorV2()
    n_scores = np.array([detector.predict(x.reshape(1, -1))[0] for x in normal])
    a_scores = np.array([detector.predict(x.reshape(1, -1))[0] for x in attack])

print(f"amostras: {len(n_scores)} normais, {len(a_scores)} ataques (sintéticos)")
for t in (0.30, 0.50, 0.70, 0.85):
    fp = np.mean(n_scores >= t) * 100
    tp = np.mean(a_scores >= t) * 100
    print(f"limiar {t:.2f}: falso positivo {fp:5.1f}% | detecção {tp:5.1f}%")
