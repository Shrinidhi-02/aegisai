"""Train the AegisAI ML injection classifier."""

from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline


BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset.csv"
MODEL_PATH = BASE_DIR / "model.pkl"


def main() -> None:
    """Train and save the injection detection model."""

    # Load the labelled dataset.
    df = pd.read_csv(DATASET_PATH)

    # Separate input text and target labels.
    X = df["text"]
    y = df["label"]

    # Split data into training and testing sets.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        stratify=y,
        random_state=42,
    )

    # Build an ML pipeline:
    # TF-IDF extracts character patterns,
    # Logistic Regression performs classification.
    model = make_pipeline(
        TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
        ),
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        ),
    )

    # Train the model.
    model.fit(X_train, y_train)

    # Evaluate the model on unseen test data.
    predictions = model.predict(X_test)

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=["normal", "attack"],
            zero_division=0,
        )
    )

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    # Save the trained model.
    joblib.dump(model, MODEL_PATH)

    print(f"\nModel saved to: {MODEL_PATH}")


if __name__ == "__main__":
    main()