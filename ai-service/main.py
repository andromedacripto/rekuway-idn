"""
FastAPI V2 - Production Ready

MUDANÇAS CRÍTICAS:
✅ Thresholds ajustados (0.30 → 0.50 → 0.70 → 0.85)
✅ Explicabilidade: cada resposta inclui reasoning
✅ Preparado para SOC invisível (Phase 2)
✅ Métricas de performance para monitoramento
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
import time
import numpy as np

from model import AnomalyDetectorV2
from features import FeatureExtractor

# Inicializa FastAPI
app = FastAPI(
    title="Rekuway IDN - AI Service V2",
    description="Behavioral Anomaly Detection - Production Ready",
    version="2.1.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inicializa modelo e extrator
model = AnomalyDetectorV2()
feature_extractor = FeatureExtractor()

# Métricas de performance
request_count = 0
total_inference_time = 0.0


# === SCHEMAS ===

class FeatureRequest(BaseModel):
    """Schema de entrada"""
    features: Dict[str, float] = Field(
        ...,
        example={
            "attempt_interval_ms": 320,
            "attempt_count": 0,
            "total_attempts": 0,
            "regenerations": 0,
            "ip_change": 0,
            "fingerprint_reuse": 0,
            "user_agent_entropy": 0.65,
            "endpoint_sequence_score": 0.85,
            "hour_of_day": 14
        }
    )


class AnalysisResponse(BaseModel):
    """Schema de resposta com explicabilidade"""
    threatScore: float = Field(..., ge=0.0, le=1.0)
    confidence: str = Field(..., pattern="^(low|medium|high)$")
    recommendedAction: str = Field(..., pattern="^(ALLOW|REGENERATE|LIE|KILL)$")
    topFactors: List[str]
    inferenceTimeMs: float
    explanation: Dict = Field(
        ...,
        description="Explicação detalhada da decisão",
        example={
            "base_score": 0.15,
            "boosters_applied": [("bot_speed", 0.20)],
            "final_score": 0.35,
            "reasoning": "Automated request pattern detected"
        }
    )


# === ENDPOINTS ===

@app.get("/")
async def root():
    """Health check"""
    global request_count, total_inference_time
    
    avg_inference = (total_inference_time / request_count) if request_count > 0 else 0
    
    return {
        "service": "Rekuway IDN - AI Service V2",
        "version": "2.1.0",
        "status": "healthy",
        "model": "Isolation Forest V2",
        "features": 9,
        "philosophy": "Zero False Positives - Amplify Real Threats",
        "metrics": {
            "requests_processed": request_count,
            "avg_inference_ms": round(avg_inference, 2)
        }
    }


@app.get("/health")
async def health():
    """Detailed health check"""
    return {
        "status": "healthy",
        "model_loaded": model.model is not None,
        "model_trained": hasattr(model.model, 'estimators_') if model.model else False,
        "mode": "production",
        "version": "2.1.0"
    }


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: FeatureRequest):
    """
    Analisa features comportamentais e retorna threat score + ação recomendada
    
    THRESHOLDS V2 (ajustados):
    < 0.30 → ALLOW      (tráfego limpo)
    < 0.50 → REGENERATE (suspeita leve)
    < 0.70 → LIE        (suspeita confirmada)
    >= 0.85 → KILL      (ameaça crítica)
    
    Latência alvo: < 30ms
    """
    global request_count, total_inference_time
    
    start_time = time.time()
    
    try:
        # 1. Extrai e normaliza features
        features = feature_extractor.extract(request.features)
        
        # 2. Predição com explicabilidade
        threat_score, confidence, top_factors, explanation = model.predict(features)
        
        # 3. Mapeia score para ação (THRESHOLDS V2)
        recommended_action = _map_score_to_action_v2(
            threat_score, 
            request.features,
            explanation
        )
        
        # Calcula tempo de inferência
        inference_time = (time.time() - start_time) * 1000  # ms
        
        # Atualiza métricas
        request_count += 1
        total_inference_time += inference_time
        
        print(f"[ANALYZE] Score: {threat_score:.3f} | Action: {recommended_action} | Time: {inference_time:.2f}ms")
        print(f"[ANALYZE] Reasoning: {explanation.get('reasoning', 'N/A')}")
        
        return AnalysisResponse(
            threatScore=round(threat_score, 3),
            confidence=confidence,
            recommendedAction=recommended_action,
            topFactors=top_factors,
            inferenceTimeMs=round(inference_time, 2),
            explanation=explanation
        )
        
    except Exception as e:
        print(f"[ANALYZE] Error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


def _map_score_to_action_v2(
    threat_score: float, 
    raw_features: Dict[str, float],
    explanation: Dict
) -> str:
    """
    Mapeia threat score para ação defensiva V2
    
    THRESHOLDS AJUSTADOS (Production Ready):
    
    < 0.30 → ALLOW      ✅ Tráfego normal/legítimo
    < 0.50 → REGENERATE ⚠️ Suspeita leve (proativo)
    < 0.70 → LIE        🎭 Suspeita confirmada (engana atacante)
    >= 0.85 → KILL      💀 Ameaça crítica (destruição)
    
    NOTA: 0.70-0.84 também pode ser LIE dependendo do contexto
    """
    
    # 🔴 KILL: Padrões críticos detectados
    if _has_critical_patterns_v2(raw_features, explanation):
        print(f"[ACTION] 🔴 CRITICAL PATTERNS → KILL")
        return "KILL"
    
    # 🔴 KILL: Threat score altíssimo
    if threat_score >= 0.85:
        print(f"[ACTION] 🔴 Critical threat ({threat_score:.3f}) → KILL")
        return "KILL"
    
    # 🟡 LIE: Threat score alto
    if threat_score >= 0.70:
        print(f"[ACTION] 🟡 High threat ({threat_score:.3f}) → LIE")
        return "LIE"
    
    # 🟢 REGENERATE: Suspeita leve
    if threat_score >= 0.50:
        print(f"[ACTION] 🟢 Medium threat ({threat_score:.3f}) → REGENERATE")
        return "REGENERATE"
    
    # ⬇️ THRESHOLD MAIS ALTO: Permite mais tráfego legítimo
    if threat_score >= 0.30:
        print(f"[ACTION] ⚠️ Low threat ({threat_score:.3f}) → REGENERATE")
        return "REGENERATE"
    
    # ✅ ALLOW: Tráfego limpo
    print(f"[ACTION] ✅ Clean traffic ({threat_score:.3f}) → ALLOW")
    return "ALLOW"


def _has_critical_patterns_v2(
    raw_features: Dict[str, float],
    explanation: Dict
) -> bool:
    """
    Detecta padrões CRÍTICOS que exigem KILL imediato
    
    PADRÕES V2 (ajustados):
    1. Velocidade extrema (< 200ms) + múltiplas tentativas
    2. Regenerações + tentativas altas (atacante persistente)
    3. IP change + fingerprint reuse + velocidade (ataque distribuído)
    4. Múltiplas tentativas após regeneração (2+)
    """
    
    # PADRÃO 1: Bot ultra-rápido com tentativas
    if (raw_features.get('attempt_interval_ms', 1000) < 200 and
        raw_features.get('attempt_count', 0) >= 3):
        print(f"[CRITICAL] 🔴 Ultra-fast bot with multiple attempts")
        return True
    
    # PADRÃO 2: Atacante persistente (regenerou + continua tentando)
    regenerations = raw_features.get('regenerations', 0)
    total_attempts = raw_features.get('total_attempts', 0)
    if regenerations > 0 and total_attempts > 8:
        print(f"[CRITICAL] 🔴 Persistent attacker ({regenerations} regens, {total_attempts} attempts)")
        return True
    
    # PADRÃO 3: Ataque distribuído sofisticado
    ip_change = raw_features.get('ip_change', 0)
    fingerprint_reuse = raw_features.get('fingerprint_reuse', 0)
    interval = raw_features.get('attempt_interval_ms', 1000)
    if ip_change > 0 and fingerprint_reuse > 0 and interval < 1000:
        print(f"[CRITICAL] 🔴 Sophisticated distributed attack")
        return True
    
    # PADRÃO 4: Múltiplas tentativas pós-regeneração
    attempt_count = raw_features.get('attempt_count', 0)
    if regenerations > 0 and attempt_count >= 2:
        print(f"[CRITICAL] 🔴 Multiple attempts after regeneration")
        return True
    
    return False


# === STARTUP ===

@app.on_event("startup")
async def startup_event():
    """Inicialização do serviço"""
    print("=" * 70)
    print("🔐 Rekuway IDN - AI Service V2 Starting (Production Ready)")
    print("=" * 70)
    print(f"Model loaded: {model.model is not None}")
    print(f"Model trained: {hasattr(model.model, 'estimators_') if model.model else False}")
    print("Philosophy: Zero False Positives - Amplify Real Threats")
    print("=" * 70)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")