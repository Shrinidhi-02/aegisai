"""Run defensive red-team tests against AegisAI."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_PATH = PROJECT_ROOT / "backend"

sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(BACKEND_PATH))

from app.detectors.injection import scan_rules
from redteam.test_payloads import RED_TEAM_PAYLOADS


def run_red_team_tests() -> None:
    """Run all defensive red-team payloads."""

    passed = 0

    total = len(RED_TEAM_PAYLOADS)

    print("AegisAI Red-Team Test Suite")
    print("=" * 40)

    for payload in RED_TEAM_PAYLOADS:
        _, detected_threats = scan_rules(payload["text"])

        expected = payload["expected_threat"]

        if expected in detected_threats:
            result = "PASS"
            passed += 1
        else:
            result = "FAIL"

        print(f"{result}: {payload['name']}")
        print(f"  Expected: {expected}")
        print(f"  Detected: {detected_threats}")
        print()

    print("=" * 40)
    print(f"Result: {passed}/{total} tests passed")


if __name__ == "__main__":
    run_red_team_tests()