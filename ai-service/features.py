"""
Feature Engineering para Rekuway IDN
Extrai e normaliza features comportamentais

CONTRATO DE FEATURES (fonte única; o cliente TypeScript em
src/services/railwayAiClient.ts envia exatamente estas 9 chaves):

  attempt_interval_ms, attempt_count, total_attempts, regenerations,
  ip_change, fingerprint_reuse, user_agent_entropy,
  endpoint_sequence_score, hour_of_day (UTC)

Chaves ausentes valem 0; chaves extras são ignoradas. Mudar o contrato
exige retreinar o modelo (train.py) e atualizar o cliente TS junto.
"""

from typing import Dict
import numpy as np


class FeatureExtractor:
    """Extrai e normaliza features para o modelo"""
    
    def __init__(self):
        # Ranges esperados para normalização
        self.feature_ranges = {
            'attempt_interval_ms': (0, 10000),
            'attempt_count': (0, 10),
            'total_attempts': (0, 20),
            'regenerations': (0, 5),
            'ip_change': (0, 1),
            'fingerprint_reuse': (0, 1),
            'user_agent_entropy': (0, 1),
            'endpoint_sequence_score': (0, 1),
            'hour_of_day': (0, 23)
        }
    
    def extract(self, raw_features: Dict) -> np.ndarray:
        """
        Extrai e normaliza features
        
        Args:
            raw_features: Dict com features brutas do Node.js
            
        Returns:
            Array numpy normalizado [9 features]
        """
        try:
            feature_order = [
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
            
            values = []
            for feature_name in feature_order:
                value = raw_features.get(feature_name, 0)
                normalized = self._normalize(feature_name, value)
                values.append(normalized)
            
            return np.array(values).reshape(1, -1)
            
        except Exception as e:
            print(f"[FEATURE_EXTRACTOR] Error: {e}")
            return np.zeros((1, 9))
    
    def _normalize(self, feature_name: str, value: float) -> float:
        """Normaliza feature para range [0, 1]"""
        min_val, max_val = self.feature_ranges[feature_name]
        value = max(min_val, min(max_val, value))
        
        if max_val == min_val:
            return 0.0
        
        return (value - min_val) / (max_val - min_val)