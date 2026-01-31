"""
Script de treinamento do Isolation Forest
Gera dados sintéticos de tráfego NORMAL + ANÔMALO

🎯 FILOSOFIA REKUWAY IDN:
O modelo precisa aprender a diferença entre:
- Tráfego legítimo (intervalos longos, poucas tentativas)
- Ataques (tentativas rápidas, persistência, múltiplos IPs)
"""

import numpy as np
from model import AnomalyDetector
from features import FeatureExtractor


def generate_normal_traffic(n_samples: int = 800) -> np.ndarray:
    """
    Gera dados sintéticos de tráfego NORMAL (80% do dataset)
    Simula comportamento legítimo de usuários
    """
    print(f"[TRAIN] Generating {n_samples} NORMAL traffic samples...")
    
    samples = []
    
    for _ in range(n_samples):
        # Tráfego normal tem:
        # - Intervalos maiores entre tentativas (1-10s)
        # - Poucas tentativas por identidade (0-2)
        # - Baixo total de tentativas (0-3)
        # - Sem regenerações ou muito poucas
        # - Sem mudança de IP
        # - Sem reuso de fingerprint
        # - User agent com entropia razoável
        # - Sequência de endpoints normal
        # - Distribuição uniforme de horários
        
        sample = [
            np.random.uniform(1000, 10000),  # attempt_interval_ms: 1-10s
            np.random.choice([0, 0, 0, 1]),  # attempt_count: maioria 0
            np.random.choice([0, 0, 1, 2]),  # total_attempts: 0-2
            0,                                # regenerations: sem regeneração
            0,                                # ip_change: sem mudança
            0,                                # fingerprint_reuse: sem reuso
            np.random.uniform(0.4, 0.8),     # user_agent_entropy: normal
            np.random.uniform(0.8, 1.0),     # endpoint_sequence_score: sequência correta
            np.random.randint(0, 24)         # hour_of_day: distribuído
        ]
        
        samples.append(sample)
    
    # Normaliza features
    extractor = FeatureExtractor()
    normalized_samples = []
    
    for sample in samples:
        features_dict = {
            'attempt_interval_ms': sample[0],
            'attempt_count': sample[1],
            'total_attempts': sample[2],
            'regenerations': sample[3],
            'ip_change': sample[4],
            'fingerprint_reuse': sample[5],
            'user_agent_entropy': sample[6],
            'endpoint_sequence_score': sample[7],
            'hour_of_day': sample[8]
        }
        
        normalized = extractor.extract(features_dict)
        normalized_samples.append(normalized[0])
    
    return np.array(normalized_samples)


def generate_anomalous_traffic(n_samples: int = 200) -> np.ndarray:
    """
    Gera dados sintéticos de tráfego ANÔMALO (20% do dataset)
    Simula comportamento de atacantes
    
    🚨 PADRÕES DE ATAQUE:
    1. Brute force (tentativas rápidas)
    2. Atacante persistente (regenerações + tentativas)
    3. Ataque distribuído (IP change + fingerprint reuse)
    4. Bot attacks (baixa entropia UA + velocidade)
    """
    print(f"[TRAIN] Generating {n_samples} ANOMALOUS traffic samples...")
    
    samples = []
    extractor = FeatureExtractor()
    
    for i in range(n_samples):
        # Escolhe tipo de ataque
        attack_type = i % 4
        
        if attack_type == 0:
            # 🔴 TIPO 1: Brute Force (tentativas muito rápidas)
            sample = [
                np.random.uniform(50, 500),      # attempt_interval_ms: 50-500ms (RÁPIDO)
                np.random.randint(3, 10),        # attempt_count: 3-10 tentativas
                np.random.randint(5, 20),        # total_attempts: 5-20
                np.random.choice([0, 1]),        # regenerations: pode ter
                0,                                # ip_change: sem mudança
                0,                                # fingerprint_reuse: sem reuso
                np.random.uniform(0.1, 0.3),     # user_agent_entropy: baixa (bot)
                np.random.uniform(0.3, 0.7),     # endpoint_sequence_score: suspeito
                np.random.choice([2, 3, 4, 22, 23])  # hour_of_day: horários suspeitos
            ]
        
        elif attack_type == 1:
            # 🔴 TIPO 2: Atacante Persistente (regenerações + tentativas)
            sample = [
                np.random.uniform(500, 2000),    # attempt_interval_ms: razoável
                np.random.randint(2, 6),         # attempt_count: 2-6
                np.random.randint(8, 20),        # total_attempts: ALTO
                np.random.randint(1, 3),         # regenerations: TEM REGENERAÇÕES
                np.random.choice([0, 1]),        # ip_change: pode mudar
                np.random.choice([0, 1]),        # fingerprint_reuse: pode reusar
                np.random.uniform(0.2, 0.5),     # user_agent_entropy: baixa-média
                np.random.uniform(0.5, 0.8),     # endpoint_sequence_score: ok
                np.random.randint(0, 24)         # hour_of_day: qualquer
            ]
        
        elif attack_type == 2:
            # 🔴 TIPO 3: Ataque Distribuído (múltiplos IPs)
            sample = [
                np.random.uniform(300, 1500),    # attempt_interval_ms: médio
                np.random.randint(2, 5),         # attempt_count: 2-5
                np.random.randint(4, 15),        # total_attempts: 4-15
                np.random.choice([0, 1, 2]),     # regenerations: pode ter
                1,                                # ip_change: SEMPRE muda IP
                1,                                # fingerprint_reuse: SEMPRE reusa
                np.random.uniform(0.2, 0.6),     # user_agent_entropy: baixa-média
                np.random.uniform(0.4, 0.7),     # endpoint_sequence_score: suspeito
                np.random.randint(0, 24)         # hour_of_day: qualquer
            ]
        
        else:
            # 🔴 TIPO 4: Bot Avançado (padrão misto)
            sample = [
                np.random.uniform(100, 800),     # attempt_interval_ms: rápido
                np.random.randint(3, 8),         # attempt_count: 3-8
                np.random.randint(6, 18),        # total_attempts: 6-18
                np.random.randint(0, 2),         # regenerations: pode ter
                np.random.choice([0, 1]),        # ip_change: pode mudar
                np.random.choice([0, 1]),        # fingerprint_reuse: pode reusar
                np.random.uniform(0.05, 0.25),   # user_agent_entropy: MUITO baixa
                np.random.uniform(0.2, 0.6),     # endpoint_sequence_score: suspeito
                np.random.choice([1, 2, 3, 4, 23])  # hour_of_day: madrugada
            ]
        
        # Normaliza
        features_dict = {
            'attempt_interval_ms': sample[0],
            'attempt_count': sample[1],
            'total_attempts': sample[2],
            'regenerations': sample[3],
            'ip_change': sample[4],
            'fingerprint_reuse': sample[5],
            'user_agent_entropy': sample[6],
            'endpoint_sequence_score': sample[7],
            'hour_of_day': sample[8]
        }
        
        normalized = extractor.extract(features_dict)
        samples.append(normalized[0])
    
    return np.array(samples)


def main():
    """Treina modelo com dados sintéticos BALANCEADOS"""
    print("=" * 70)
    print("🔥 REKUWAY IDN - AGGRESSIVE MODEL TRAINING")
    print("=" * 70)
    print("Philosophy: Learn to detect attacks aggressively")
    print("Dataset: 80% Normal + 20% Anomalous")
    print("=" * 70)
    
    # Gera dados de tráfego NORMAL (80%)
    X_normal = generate_normal_traffic(n_samples=800)
    print(f"[TRAIN] ✅ Normal traffic data: {X_normal.shape}")
    
    # Gera dados de tráfego ANÔMALO (20%)
    X_anomalous = generate_anomalous_traffic(n_samples=200)
    print(f"[TRAIN] ✅ Anomalous traffic data: {X_anomalous.shape}")
    
    # Combina datasets
    X_train = np.vstack([X_normal, X_anomalous])
    print(f"[TRAIN] ✅ Combined training data: {X_train.shape}")
    
    # Embaralha
    np.random.shuffle(X_train)
    print(f"[TRAIN] 🔀 Shuffled dataset")
    
    # Treina modelo
    detector = AnomalyDetector()
    detector.train(X_train)
    
    print("=" * 70)
    print("✅ TRAINING COMPLETE!")
    print("=" * 70)
    print(f"Model saved to: {detector.model_path}")
    print(f"Training samples: {len(X_train)}")
    print(f"  ├─ Normal: {len(X_normal)} (80%)")
    print(f"  └─ Anomalous: {len(X_anomalous)} (20%)")
    print("")
    print("🔥 Model is now AGGRESSIVE and ready to protect Rekuway IDN!")
    print("")
    print("You can now start the API service:")
    print("  python main.py")
    print("  or")
    print("  uvicorn main:app --reload --port 8000")
    print("=" * 70)


if __name__ == "__main__":
    main()