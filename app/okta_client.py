import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

class OktaClientError(Exception):
    """
    Safe, application-level Okta client error.
    """

class OktaClient:
    def __init__(self):
        domain = os.getenv("OKTA_DOMAIN", "").strip()
        token = os.getenv("OKTA_API_TOKEN", "").strip()

        if not domain or not token:
            raise OktaClientError(
                "Okta configuration is missing. Set OKTA_DOMAIN "
                "and OKTA_API_TOKEN in your local .env file."
            )

        url = urlparse(
            domain if "://" in domain else f"https://{domain}"
        )

        if (
            url.scheme != "https"
            or not url.hostname
            or url.path not in ("", "/")
            or url.query
            or url.fragment
            or url.username
            or url.password
        ):
            raise OktaClientError(
                "OKTA_DOMAIN must be an HTTPS Okta hostname."
            )

        hostname = url.hostname.lower()
        if not hostname.endswith(".okta.com"):
            raise OktaClientError(
                "This initial client only accepts standard "
                "Okta-hosted .okta.com domains."
            )

        self.base_url = f"https://{hostname}"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"SSWS {token}",
            "Accept": "application/json",
        })

    def get_system_logs(self, hours: int = 24, limit: int = 100) -> list[dict]:
        hrs = max(1, min(hours, 168))
        lmt = max(1, min(limit, 1000))

        time = (
            datetime.now(timezone.utc) - timedelta(hours=hrs)
        ).isoformat(timespec="seconds").replace("+00:00", "Z")

        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/logs",
                params={"time": time, "limit": lmt},
                timeout=20,
            )
        except requests.RequestException as exc:
            raise OktaClientError(
                f"Could not connect to Okta ({type(exc).__name__})."
            ) from None

        if response.status_code == 401:
            raise OktaClientError(
                "Okta rejected the credential. Check its type and validity."
            )

        if response.status_code == 403:
            raise OktaClientError(
                "Access denied. Verify the credential's permissions."
            )

        if not response.ok:
            raise OktaClientError(
                f"Okta returned HTTP {response.status_code}."
            )

        try:
            data = response.json()
        except ValueError:
            raise OktaClientError(
                "Okta returned an unexpected response format."
            ) from None

        if not isinstance(data, list):
            raise OktaClientError(
                "Expected a list of System Log events from Okta."
            )

        return data