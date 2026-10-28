from typing import Any

PRIVILEGE_EVENTS = {
    "user.account.privilege.grant",
    "group.privilege.grant",
    "iam.role.permissions.add",
}

API_TOKEN_EVENTS = {
    "system.api_token.create",
}

def analyze_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []

    for event in events:
        event_type = event.get("eventType", "")
        outcome = (event.get("outcome") or {}).get("result")
        actor = event.get("actor") or {}

        finding = None

        if event_type in PRIVILEGE_EVENTS:
            finding = {
                "category": "privilege_change",
                "severity": "high",
                "reason": "An event associated with granting or changing privileges was recorded.",
            }
        elif event_type in API_TOKEN_EVENTS:
            finding = {
                "category": "api_token_created",
                "severity": "high",
                "reason": "An Okta API token creation event was recorded.",
            }
        elif (
            outcome == "FAILURE"
            and (
                event_type.startswith("user.authentication.")
                or event_type == "user.session.start"
                or event_type == "app.oauth2.authorize"
            )
        ):
            finding = {
                "category": "authentication_failure",
                "severity": "medium",
                "reason": "A failed authentication or OAuth authorization event needs review.",
            }

        if finding:
            client = event.get("client") or {}
            targets = event.get("target") or []
            debug_data = (
                (event.get("debugContext") or {}).get("debugData") or {}
            )

            findings.append({
                "event_id": event.get("uuid"),
                "event_type": event_type,
                "published": event.get("published"),
                "outcome": outcome,
                "actor_type": actor.get("type"),
                "actor_id": actor.get("id"),
                "actor_login": (actor.get("alternateId")),
                "client_ip": client.get("ipAddress"),
                "target": [
                    {
                        "id": item.get("id"),
                        "type": item.get("type"),
                        "name": item.get("displayName"),
                    }
                    for item in targets
                ],
                "debug_context": {
                    key: debug_data.get(key)
                    for key in ("requestId", "requestUri", "factor", "reason")
                    if debug_data.get(key) is not None
                },
                **finding,
            })

    return findings


def prioritize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Sort findings by transparent, rule-based investigation priority.
    """
    priority = {
        "privilege_change": 3,
        "api_token_created": 3,
        "authentication_failure": 2,
    }

    return sorted(
        findings,
        key=lambda item: (
            priority.get(item.get("category", ""), 0),
            item.get("published", ""),
        ),
        reverse=True,
    )