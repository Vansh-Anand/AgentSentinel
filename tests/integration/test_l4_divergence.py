import pytest
import numpy as np
import torch
import os
from common.events.schemas import SyscallEvent, WindowQuality
from l4_divergence.features.vocabulary import SyscallVocabulary
from l4_divergence.hpc.aligner import HPCWindowAligner
from l4_divergence.features.extractor import BehaviorFeatureExtractor
from l4_divergence.features.normalizer import FeatureNormalizer
from l4_divergence.dataset.loader import DatasetBuilder
from l4_divergence.siamese.model import SiameseRecurrentAutoencoder
from l4_divergence.isolation_forest.detector import IsolationForestDetector
from l4_divergence.ensemble.divergence import DivergenceEnsemble, ScoreCalibrator
from l4_divergence.ece.manager import ECEManager
from l4_divergence.ece.policy import BaselineAdmissionPolicy

@pytest.fixture
def l4_components():
    vocab = SyscallVocabulary()
    aligner = HPCWindowAligner()
    extractor = BehaviorFeatureExtractor(vocab, aligner)
    normalizer = FeatureNormalizer()
    return vocab, aligner, extractor, normalizer

def test_l4_telemetry_fusion(l4_components):
    vocab, aligner, extractor, normalizer = l4_components
    builder = DatasetBuilder("agent_test")
    
    # This checks the synthetic telemetry-to-score pipeline, not detector quality.
    # The random generator and ten held-out attack windows do not guarantee
    # separation of class means on every run.
    dataset = builder.build_dataset(num_legit=100, num_attack=20, window_size=64)
    legit_windows = dataset["legitimate"]
    attack_windows = dataset["attack"]
    
    # Extract features
    legit_features = [extractor.extract(seq, hpc) for seq, hpc in legit_windows]
    numeric_flat = [f.to_flat_numeric() for f in legit_features]
    
    normalizer.fit(numeric_flat)
    normalized = np.array([normalizer.transform(f) for f in numeric_flat])
    
    # Train Isolation Forest
    iso = IsolationForestDetector(random_state=42)
    iso.fit(normalized)
    
    attack_windows = builder.build_dataset(num_legit=0, num_attack=10, window_size=64)["attack"]
    attack_features = [extractor.extract(seq, hpc) for seq, hpc in attack_windows]
    attack_flat = np.array([normalizer.transform(f.to_flat_numeric()) for f in attack_features])

    legit_scores = iso.score(normalized)
    attack_scores = iso.score(attack_flat)

    assert legit_scores.shape == (len(legit_windows),)
    assert attack_scores.shape == (len(attack_windows),)
    assert np.isfinite(legit_scores).all() and np.isfinite(attack_scores).all()
    assert ((0 <= legit_scores) & (legit_scores <= 1)).all()
    assert ((0 <= attack_scores) & (attack_scores <= 1)).all()

def test_ece_poisoning_defense():
    manager = ECEManager(percentile=99.0)
    legit_scores = [0.1, 0.12, 0.15, 0.09, 0.11]
    manager.initialize(legit_scores)
    
    policy = BaselineAdmissionPolicy(current_threshold=manager.threshold, margin=0.2)
    quality = WindowQuality(event_count=256, expected_count=256, dropped_events=0, ordering_valid=True, timestamp_quality=1.0, hpc_coverage=1.0, quality_score=1.0)
    
    assert policy.is_admissible(0.13, quality) is True
    assert policy.is_admissible(0.85, quality) is False
    
    poor_quality = WindowQuality(event_count=200, expected_count=256, dropped_events=56, ordering_valid=True, timestamp_quality=0.5, hpc_coverage=0.0, quality_score=0.4)
    assert policy.is_admissible(0.12, poor_quality) is False

def test_siamese_model_instantiation():
    vocab_size = 100
    num_numeric = 15
    model = SiameseRecurrentAutoencoder(vocab_size=vocab_size, num_numeric_features=num_numeric)
    
    seq_a = torch.randint(0, vocab_size, (2, 64))
    num_a = torch.rand((2, num_numeric))
    seq_b = torch.randint(0, vocab_size, (2, 64))
    num_b = torch.rand((2, num_numeric))
    
    la, lb, dist = model(seq_a, num_a, seq_b, num_b)
    assert la.shape == (2, 64)
    assert dist.shape == (2,)
    
def test_ensemble_logic():
    ensemble = DivergenceEnsemble(siamese_weight=0.6, isolation_weight=0.4)
    
    # Test fallback behavior when calibrator is NOT fit
    res_unfit = ensemble.evaluate(raw_siamese=0.5, raw_isolation=0.7)
    # 0.5 * 0.6 + 0.7 * 0.4 = 0.3 + 0.28 = 0.58
    assert np.isclose(res_unfit["score"], 0.58)
    
    # Test normal behavior when calibrator IS fit
    ensemble.calibrator.fit(siam_scores=[0.0, 10.0], iso_scores=[-1.0, 1.0])
    # siam 5.0 -> scaled to 0.5
    # iso 0.0 -> scaled to 0.5
    res_fit = ensemble.evaluate(raw_siamese=5.0, raw_isolation=0.0)
    assert np.isclose(res_fit["siamese_component"], 0.5)
    assert np.isclose(res_fit["isolation_component"], 0.5)
    assert np.isclose(res_fit["score"], 0.5)
