"""Testes do modo de ambiente do detector (produção vs desenvolvimento)."""

import contextlib
import io

import numpy as np
import pytest

from model import AnomalyDetectorV2


def make_detector(monkeypatch, env):
    if env is None:
        monkeypatch.delenv("ENVIRONMENT", raising=False)
    else:
        monkeypatch.setenv("ENVIRONMENT", env)
    with contextlib.redirect_stdout(io.StringIO()):
        return AnomalyDetectorV2()


@pytest.mark.parametrize("env", ["development", "dev", "local", "test", " Development "])
def test_valores_de_desenvolvimento_explicitos(monkeypatch, env):
    assert make_detector(monkeypatch, env).is_development is True


@pytest.mark.parametrize("env", [None, "", "production", "PRODUCTION", "staging", "prod", "qualquer"])
def test_ausente_ou_desconhecido_conta_como_producao(monkeypatch, env):
    # Falha segura: sem configuração, as defesas de produção ficam LIGADAS.
    assert make_detector(monkeypatch, env).is_development is False


# [attempt_interval_ms, attempt_count, total_attempts, regenerations, ip_change,
#  fingerprint_reuse, user_agent_entropy, endpoint_sequence_score, hour_of_day]
DISTRIBUTED = np.array([[200, 6, 6, 1, 1, 1, 0.5, 0.5, 12]], dtype=float)


def test_ataque_distribuido_pontua_mais_em_producao(monkeypatch):
    prod = make_detector(monkeypatch, "production")
    dev = make_detector(monkeypatch, "development")
    with contextlib.redirect_stdout(io.StringIO()):
        score_prod = prod.predict(DISTRIBUTED)[0]
        score_dev = dev.predict(DISTRIBUTED)[0]
    assert score_prod > score_dev
