import numpy as np
import pytest

from gateway.model import (MAX_SAMPLES, N_TREES, THRESHOLD_PERCENTILE, DeviceModel, ModelBank, risk_score,
                           threshold_from_scores)


def baseline(n, seed=0):
    rng = np.random.default_rng(seed)
    return rng.normal(loc=[400, 200, 3, 100, 2, 2, 0, 0, 0, 0.3], scale=[40, 20, 1, 10, .3, .3, .01, .01, .01, .05],
                      size=(n, 10))


def test_settings_match_design():
    assert N_TREES == 100
    assert MAX_SAMPLES == 256
    assert THRESHOLD_PERCENTILE == 99.82
    m = DeviceModel("d").fit(baseline(2000), baseline(1000, 1))
    assert m.forest.n_estimators == 100
    assert m.forest.max_samples == 256


def test_threshold_is_9982_percentile_of_calibration_scores():
    scores = np.linspace(0, 1, 10001)  # 0.0000, 0.0001, ...
    assert threshold_from_scores(scores) == pytest.approx(0.9982)

    m = DeviceModel("d").fit(baseline(2000), baseline(5000, 1))
    calib_scores = m.anomaly_scores(baseline(5000, 1))
    assert m.threshold == pytest.approx(np.percentile(calib_scores, 99.82))
    # about 0.18% of calibration windows sit at or above the threshold (Eq. 11)
    assert np.mean(calib_scores >= m.threshold) == pytest.approx(0.0018, abs=0.001)


def test_scores_are_s_between_0_and_1_and_risk_is_100s():
    m = DeviceModel("d").fit(baseline(1000), baseline(1000, 1))
    s = m.anomaly_scores(baseline(50, 2))
    assert np.all((s > 0) & (s < 1))
    out = m.score(baseline(1, 3)[0])
    assert out.risk == pytest.approx(100 * out.score, abs=0.05)
    assert risk_score(0.7234) == 72.3


def test_outlier_is_flagged_normal_is_not():
    m = DeviceModel("d").fit(baseline(2000), baseline(1000, 1))
    normal = baseline(1, 9)[0]
    attack = normal.copy()
    attack[[0, 4, 5, 6, 7, 8]] = [50_000, 40, 300, 3, 300, 1.0]
    assert not m.score(normal).flagged
    assert m.score(attack).flagged
    assert m.score(attack).risk > m.score(normal).risk


def test_small_baseline_uses_all_samples():
    m = DeviceModel("d").fit(baseline(100))
    assert m.forest.max_samples == 100


def test_bank_save_and_load(tmp_path):
    bank = ModelBank()
    bank.train("192.168.50.11", baseline(500), baseline(300, 1))
    assert bank.score("192.168.50.99", baseline(1)[0]) is None  # unregistered: no model
    bank.save(tmp_path)
    again = ModelBank.load(tmp_path)
    x = baseline(1, 5)[0]
    assert again.score("192.168.50.11", x).score == pytest.approx(bank.score("192.168.50.11", x).score)
