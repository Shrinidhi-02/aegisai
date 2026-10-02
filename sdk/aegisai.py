"""Python SDK for calling the AegisAI security gateway."""

from typing import Any

import requests


class AegisAIClient:
    """Client for interacting with the AegisAI scanning API."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: int = 10,
    ) -> None:
        """Initialize the AegisAI client."""

        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        }

    def _scan(
        self,
        endpoint: str,
        text: str,
        user_id: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Send text to an AegisAI scanning endpoint."""

        payload = {
            "text": text,
            "user_id": user_id,
            "session_id": session_id,
        }

        response = requests.post(
            f"{self.base_url}{endpoint}",
            json=payload,
            headers=self.headers,
            timeout=self.timeout,
        )

        response.raise_for_status()

        return response.json()

    def scan_input(
        self,
        text: str,
        user_id: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Scan a user prompt before sending it to an AI model."""

        return self._scan(
            endpoint="/api/v1/scan-input",
            text=text,
            user_id=user_id,
            session_id=session_id,
        )

    def scan_output(
        self,
        text: str,
        user_id: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Scan an AI response before returning it to the user."""

        return self._scan(
            endpoint="/api/v1/scan-output",
            text=text,
            user_id=user_id,
            session_id=session_id,
        )