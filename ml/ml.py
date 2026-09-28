"""Machine-learning inference utilities for AegisAI."""

from functools import lru_cache
from pathlib import Path

import joblib


MODEL_PATH = Path(__file__).resolve().parent / "model.pkl"


@lru_cache(maxsize=1)
def load_model():
    """Load the trusted AegisAI ML model once."""

    return joblib.load(MODEL_PATH)


def predict_attack_probability(text: str) -> float:
    """Return the probability that text is a prompt injection attack."""

    model = load_model()

    probabilities = model.predict_proba([text])[0]

    # Class 1 represents an attack.
    attack_probability = probabilities[1]

    return float(attack_probability)


def ml_score(text: str) -> int:
    """Convert attack probability into a 0-100 ML security score."""

    probability = predict_attack_probability(text)

    return round(probability * 100)