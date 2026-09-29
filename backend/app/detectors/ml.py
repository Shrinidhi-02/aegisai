"""ML-based prompt injection detector for AegisAI."""

from functools import lru_cache
from pathlib import Path

import joblib


MODEL_PATH = Path(__file__).resolve().parents[3] / "ml" / "model.pkl"


@lru_cache(maxsize=1)
def load_model():
    """Load the trusted trained model once."""

    return joblib.load(MODEL_PATH)


def predict_attack_probability(text: str) -> float:
    """Return the probability that text is an attack."""

    model = load_model()

    probabilities = model.predict_proba([text])[0]

    return float(probabilities[1])


def ml_score(text: str) -> int:
    """Convert attack probability to a 0-100 score."""

    probability = predict_attack_probability(text)

    return round(probability * 100)