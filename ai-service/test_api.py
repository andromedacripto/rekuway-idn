"""Testes do contrato HTTP do ai-service: autenticação, CORS e formato da resposta."""

import importlib
import os

import pytest
from fastapi.testclient import TestClient

FEATURES = {
    "attempt_interval_ms": 150,
    "attempt_count": 4,
    "total_attempts": 6,
    "regenerations": 0,
    "ip_change": 0,
    "fingerprint_reuse": 0,
    "user_agent_entropy": 0.2,
    "endpoint_sequence_score": 0.4,
    "hour_of_day": 3,
}


def make_client(token="t0ken-de-teste", origins="https://app.rekuway.test"):
    if token is None:
        os.environ.pop("AI_SERVICE_TOKEN", None)
    else:
        os.environ["AI_SERVICE_TOKEN"] = token
    os.environ["ALLOWED_ORIGINS"] = origins
    import main

    importlib.reload(main)
    return TestClient(main.app)


def test_sem_token_recusa():
    r = make_client().post("/analyze", json={"features": FEATURES})
    assert r.status_code == 401


def test_token_errado_recusa():
    r = make_client().post(
        "/analyze", json={"features": FEATURES}, headers={"X-AI-Service-Token": "errado"}
    )
    assert r.status_code == 401


def test_servico_sem_token_configurado_falha_fechado():
    r = make_client(token=None).post(
        "/analyze", json={"features": FEATURES}, headers={"X-AI-Service-Token": ""}
    )
    assert r.status_code == 503


def test_token_correto_devolve_analise():
    r = make_client().post(
        "/analyze", json={"features": FEATURES}, headers={"X-AI-Service-Token": "t0ken-de-teste"}
    )
    assert r.status_code == 200
    body = r.json()
    assert 0 <= body["threatScore"] <= 1
    assert body["recommendedAction"] in {"ALLOW", "REGENERATE", "LIE", "KILL"}


def test_cors_somente_origens_permitidas():
    c = make_client()
    ok = c.options(
        "/analyze",
        headers={"Origin": "https://app.rekuway.test", "Access-Control-Request-Method": "POST"},
    )
    assert ok.headers.get("access-control-allow-origin") == "https://app.rekuway.test"
    bad = c.options(
        "/analyze",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in bad.headers


@pytest.mark.parametrize("path", ["/", "/health"])
def test_health_publico(path):
    assert make_client().get(path).status_code == 200
