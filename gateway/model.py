"""Per-device Isolation Forest (Section 3.5, Eqs. 11, 13 to 15).

- 100 trees, subsample size 256 (Liu et al., 2008).
- Train on baseline windows (first five days), calibrate the threshold on the
  last two days: threshold = 99.82nd percentile of calibration scores.
- Anomaly score s(x, n) is in (0, 1); sklearn's score_samples returns -s, so we
  flip the sign. Risk score shown to the owner = 100 * s.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

N_TREES = 100
MAX_SAMPLES = 256
THRESHOLD_PERCENTILE = 99.82
CONSECUTIVE_WINDOWS = 2


@dataclass
class Score:
    score: float  # s(x, n), 0..1
    risk: float  # 100 * s
    flagged: bool


class DeviceModel:
    def __init__(self, device: str, random_state: int | None = 42):
        self.device = device
        self.random_state = random_state
        self.forest: IsolationForest | None = None
        self.threshold: float | None = None

    def fit(self, baseline: np.ndarray, calibration: np.ndarray | None = None) -> "DeviceModel":
        baseline = np.asarray(baseline, dtype=float)
        self.forest = IsolationForest(
            n_estimators=N_TREES,
            max_samples=min(MAX_SAMPLES, len(baseline)),
            random_state=self.random_state,
        ).fit(baseline)
        calib = baseline if calibration is None else np.asarray(calibration, dtype=float)
        self.calibrate(calib)
        return self

    def calibrate(self, calibration: np.ndarray) -> float:
        scores = self.anomaly_scores(calibration)
        self.threshold = threshold_from_scores(scores)
        return self.threshold

    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        if self.forest is None:
            raise RuntimeError(f"model for {self.device} is not trained")
        return -self.forest.score_samples(np.asarray(X, dtype=float))

    def score(self, x) -> Score:
        if self.threshold is None:
            raise RuntimeError(f"model for {self.device} is not calibrated")
        s = float(self.anomaly_scores(np.asarray(x, dtype=float).reshape(1, -1))[0])
        return Score(score=s, risk=risk_score(s), flagged=s >= self.threshold)

    def save(self, path: str | Path) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: str | Path) -> "DeviceModel":
        return joblib.load(path)


def threshold_from_scores(scores, percentile: float = THRESHOLD_PERCENTILE) -> float:
    return float(np.percentile(np.asarray(scores, dtype=float), percentile))


def risk_score(s: float) -> float:
    return round(100.0 * s, 1)


class ModelBank:
    """One model per registered device. Unregistered clients get no model."""

    def __init__(self):
        self.models: dict[str, DeviceModel] = {}

    def train(self, device: str, baseline, calibration=None, random_state: int | None = 42) -> DeviceModel:
        m = DeviceModel(device, random_state=random_state).fit(baseline, calibration)
        self.models[device] = m
        return m

    def score(self, device: str, x) -> Score | None:
        m = self.models.get(device)
        return m.score(x) if m else None

    def save(self, folder: str | Path) -> None:
        folder = Path(folder)
        folder.mkdir(parents=True, exist_ok=True)
        for dev, m in self.models.items():
            m.save(folder / f"{dev.replace(':', '-')}.joblib")

    @classmethod
    def load(cls, folder: str | Path) -> "ModelBank":
        bank = cls()
        for f in sorted(Path(folder).glob("*.joblib")):
            m = DeviceModel.load(f)
            bank.models[m.device] = m
        return bank
