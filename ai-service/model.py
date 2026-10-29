"""
Isolation Forest V2 - Production Ready

CORREÇÕES CRÍTICAS:
✅ Thresholds ajustados para desenvolvimento local
✅ Boosters tolerantes para fingerprint_reuse (localhost ::1)
✅ Explicabilidade: cada decisão tem justificativa clara
✅ Preparado para evolução (Phase 2: supervised learning)

MOAT TÉCNICO:
- Feature engineering específico para identity attacks
- Boosters baseados em padrões reais de ataque
- Arquitetura preparada para federated learning (SOC invisível)
"""

import hashlib
import os
import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from typing import Tuple, List, Optional, Dict


class AnomalyDetectorV2:
    """
    Detector de anomalias para Rekuway IDN
    
    DESIGN PRINCIPLES:
    1. Zero falsos positivos em tráfego legítimo
    2. Detecta ataques sofisticados (não apenas brute force)
    3. Explicável (cada score tem justificativa)
    4. Evolutivo (preparado para supervised learning)
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.model: Optional[IsolationForest] = None
        self.model_path = model_path or "models/isolation_forest.joblib"
        self.feature_names = [
            'attempt_interval_ms',
            'attempt_count',
            'total_attempts',
            'regenerations',
            'ip_change',
            'fingerprint_reuse',
            'user_agent_entropy',
            'endpoint_sequence_score',
            'hour_of_day'
        ]
        
        # Configuração de ambiente (detecta localhost vs produção)
        self.is_development = self._detect_environment()
        
        if Path(self.model_path).exists():
            self.load_model()
        else:
            print("[MODEL] No trained model found. Using heuristics.")
            self._create_default_model()
    
    def _detect_environment(self) -> bool:
        """
        True só quando ENVIRONMENT indica desenvolvimento explicitamente
        (development, dev, local ou test). Qualquer outro valor, ou a variável
        ausente, conta como PRODUÇÃO: se alguém esquecer de configurar, as
        defesas ficam ligadas (booster de ataque distribuído e penalização de
        fingerprint_reuse), nunca desligadas.
        """
        env = os.getenv("ENVIRONMENT", "production").strip().lower()
        return env in {"development", "dev", "local", "test"}

    def _create_default_model(self):
        """Cria modelo padrão"""
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.08,  # 8% de anomalias esperadas
            random_state=42,
            max_samples='auto',
            bootstrap=False
        )
        print("[MODEL] Default model created (heuristic mode)")
    
    def predict(self, features: np.ndarray) -> Tuple[float, str, List[str], Dict]:
        """
        Predição com explicabilidade
        
        Returns:
            (threatScore, confidence, topFactors, explanation)
            
        explanation = {
            'boosters_applied': [...],
            'base_score': float,
            'final_score': float,
            'reasoning': str
        }
        """
        try:
            if self.model is None:
                self._create_default_model()
            
            if not hasattr(self.model, 'estimators_'):
                return self._heuristic_prediction(features)
            
            # Predição do modelo treinado
            decision = self.model.decision_function(features)[0]
            base_score = self._normalize_threat_score(decision)
            
            # Aplica boosters com explicação
            boosted_score, boosters_applied = self._apply_boosters_v2(features, base_score)
            
            confidence = self._calculate_confidence(decision, len(boosters_applied))
            top_factors = self._get_top_factors(features)
            
            explanation = {
                'base_score': round(base_score, 3),
                'boosters_applied': boosters_applied,
                'final_score': round(boosted_score, 3),
                'reasoning': self._build_reasoning(boosted_score, boosters_applied)
            }
            
            print(f"[MODEL] Prediction: {boosted_score:.3f} (base: {base_score:.3f}, boosters: {len(boosters_applied)})")
            
            return boosted_score, confidence, top_factors, explanation
            
        except Exception as e:
            print(f"[MODEL] Prediction error: {e}")
            return 0.3, "low", [], {'error': str(e)}  # ⬇️ Score neutro baixo em erro
    
    def _heuristic_prediction(self, features: np.ndarray) -> Tuple[float, str, List[str], Dict]:
        """
        Heurística quando modelo não está treinado
        
        CRITICAL: Ajustado para evitar falsos positivos
        """
        f = features[0]
        
        threat_score = 0.0
        suspicious_features = []
        boosters_applied = []
        
        # 🔴 CRÍTICO: Tentativas muito rápidas (< 500ms)
        if f[0] < 0.05:  # < 500ms normalizado
            boost = 0.35
            threat_score += boost
            suspicious_features.append('attempt_interval_ms')
            boosters_applied.append(('bot_speed', boost))
            print(f"[MODEL] 🔴 Bot-like speed detected")
        
        # 🔴 CRÍTICO: Múltiplas tentativas
        if f[1] > 0.4:  # > 4 tentativas
            boost = 0.30
            threat_score += boost
            suspicious_features.append('attempt_count')
            boosters_applied.append(('multiple_attempts', boost))
            print(f"[MODEL] 🔴 Multiple failed attempts")
        
        # 🟡 ALTO: Total de tentativas (atacante persistente)
        if f[2] > 0.5:  # > 10 tentativas total
            boost = 0.25
            threat_score += boost
            suspicious_features.append('total_attempts')
            boosters_applied.append(('persistent_attacker', boost))
            print(f"[MODEL] 🟡 Persistent attack pattern")
        
        # 🟡 ALTO: Regenerações (atacante que retornou)
        if f[3] > 0.2:  # Tem regenerações
            boost = 0.20
            threat_score += boost
            suspicious_features.append('regenerations')
            boosters_applied.append(('post_regeneration', boost))
            print(f"[MODEL] 🟡 Attack after regeneration")
        
        # 🟡 MÉDIO: Mudança de IP
        if f[4] > 0.7:  # IP change significativo
            boost = 0.15
            threat_score += boost
            suspicious_features.append('ip_change')
            boosters_applied.append(('ip_change', boost))
            print(f"[MODEL] 🟡 IP rotation detected")
        
        # 🟢 BAIXO: Fingerprint reuse (tolerante em desenvolvimento)
        if f[5] > 0.7:  # ⬆️ Threshold alto (só penaliza em prod)
            if not self.is_development:  # ✅ Só penaliza em produção
                boost = 0.10
                threat_score += boost
                suspicious_features.append('fingerprint_reuse')
                boosters_applied.append(('fingerprint_reuse', boost))
                print(f"[MODEL] 🟢 Fingerprint reuse (production)")
        
        # 🟢 BAIXO: User agent suspeito
        if f[6] < 0.2:  # Entropia muito baixa
            boost = 0.12
            threat_score += boost
            suspicious_features.append('user_agent_entropy')
            boosters_applied.append(('suspicious_ua', boost))
            print(f"[MODEL] 🟢 Suspicious user agent")
        
        # Limita a 1.0
        threat_score = min(threat_score, 1.0)
        
        # Confiança baseada em fatores detectados
        if len(suspicious_features) >= 3:
            confidence = "high"
        elif len(suspicious_features) >= 1:
            confidence = "medium"
        else:
            confidence = "low"
        
        explanation = {
            'base_score': 0.0,
            'boosters_applied': boosters_applied,
            'final_score': round(threat_score, 3),
            'reasoning': self._build_reasoning(threat_score, boosters_applied)
        }
        
        print(f"[MODEL] Heuristic: {threat_score:.3f} | Factors: {len(suspicious_features)}")
        
        return threat_score, confidence, suspicious_features[:3], explanation
    
    def _apply_boosters_v2(
        self, 
        features: np.ndarray, 
        base_score: float
    ) -> Tuple[float, List[Tuple[str, float]]]:
        """
        Aplica boosters críticos com explicação
        
        Returns:
            (boosted_score, [(booster_name, boost_amount), ...])
        """
        f = features[0]
        boosted_score = base_score
        boosters_applied = []
        
        # BOOSTER 1: Velocidade extrema (< 200ms)
        if f[0] < 0.02:
            boost = 0.20
            boosted_score += boost
            boosters_applied.append(('extreme_speed', boost))
            print(f"[MODEL] 🚀 BOOST: Extreme speed (+{boost})")
        
        # BOOSTER 2: Atacante persistente (regenerações + tentativas)
        if f[3] > 0 and f[2] > 0.5:
            boost = 0.15
            boosted_score += boost
            boosters_applied.append(('persistent_pattern', boost))
            print(f"[MODEL] 🚀 BOOST: Persistent attacker (+{boost})")
        
        # BOOSTER 3: Ataque distribuído (apenas em produção)
        if not self.is_development:
            if f[4] > 0.7 and f[5] > 0.7:  # IP change + fingerprint reuse
                boost = 0.12
                boosted_score += boost
                boosters_applied.append(('distributed_attack', boost))
                print(f"[MODEL] 🚀 BOOST: Distributed attack (+{boost})")
        
        # BOOSTER 4: Bot behavior (UA suspeito + velocidade)
        if f[6] < 0.2 and f[0] < 0.1:
            boost = 0.10
            boosted_score += boost
            boosters_applied.append(('bot_behavior', boost))
            print(f"[MODEL] 🚀 BOOST: Bot-like behavior (+{boost})")
        
        return min(boosted_score, 1.0), boosters_applied
    
    def _build_reasoning(self, score: float, boosters: List[Tuple[str, float]]) -> str:
        """Constrói explicação em linguagem natural"""
        if score < 0.3:
            return "Normal behavior pattern"
        
        if not boosters:
            return "Baseline anomaly detected"
        
        primary_booster = max(boosters, key=lambda x: x[1])
        
        reasons_map = {
            'bot_speed': 'Automated request pattern detected',
            'multiple_attempts': 'Repeated failed authentication',
            'persistent_attacker': 'Long-term attack campaign',
            'post_regeneration': 'Attack resumed after regeneration',
            'ip_change': 'IP rotation pattern',
            'fingerprint_reuse': 'Shared fingerprint across identities',
            'suspicious_ua': 'Non-standard user agent',
            'extreme_speed': 'Inhuman request velocity',
            'persistent_pattern': 'Sophisticated persistent threat',
            'distributed_attack': 'Coordinated attack from multiple sources',
            'bot_behavior': 'Automated tool detected'
        }
        
        return reasons_map.get(primary_booster[0], 'Anomalous pattern detected')
    
    def _normalize_threat_score(self, decision: float) -> float:
        """Normaliza decision para threatScore [0, 1]"""
        normalized = (0.5 - decision) / 0.8
        return max(0.0, min(1.0, normalized))
    
    def _calculate_confidence(self, decision: float, num_boosters: int) -> str:
        """Calcula confiança baseado em decision + boosters"""
        abs_decision = abs(decision)
        
        # Alta confiança: decision forte + boosters
        if abs_decision > 0.25 and num_boosters >= 2:
            return "high"
        
        # Média confiança: decision ou boosters
        if abs_decision > 0.12 or num_boosters >= 1:
            return "medium"
        
        return "low"
    
    def _get_top_factors(self, features: np.ndarray, top_n: int = 3) -> List[str]:
        """Identifica top features contribuindo para anomalia"""
        f = features[0]
        
        deviations = []
        for idx, value in enumerate(f):
            deviation = abs(value - 0.5)
            deviations.append((deviation, self.feature_names[idx]))
        
        deviations.sort(reverse=True)
        
        return [name for _, name in deviations[:top_n]]
    
    def train(self, X: np.ndarray):
        """Treina modelo com dados de tráfego"""
        print(f"[MODEL] Training with {len(X)} samples...")
        
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.08,  # 8% de anomalias
            random_state=42,
            max_samples='auto',
            bootstrap=False
        )
        
        self.model.fit(X)
        print("[MODEL] Training complete!")
        
        self.save_model()
    
    def save_model(self):
        """Salva modelo treinado"""
        Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path)
        print(f"[MODEL] Model saved to {self.model_path}")
    
    def load_model(self):
        """Carrega modelo treinado"""
        try:
            # joblib usa pickle: se MODEL_SHA256 estiver definido, só carrega o
            # arquivo cujo hash confere (protege contra troca do modelo).
            expected = os.getenv("MODEL_SHA256", "").strip().lower()
            if expected:
                actual = hashlib.sha256(Path(self.model_path).read_bytes()).hexdigest()
                if actual != expected:
                    raise ValueError("model file hash mismatch (MODEL_SHA256)")
            self.model = joblib.load(self.model_path)
            print(f"[MODEL] Model loaded from {self.model_path}")
        except Exception as e:
            print(f"[MODEL] Error loading model: {e}")
            self._create_default_model()


# Alias para compatibilidade
AnomalyDetector = AnomalyDetectorV2