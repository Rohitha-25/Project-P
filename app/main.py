from fastapi import FastAPI, HTTPException, Query

from app.okta_client import OktaClient, OktaClientError
from app.monitor import analyze_events, prioritize_findings
from app.investigator import investigate_finding

app = FastAPI(
    title="Project-P",
    description=(
        "AI-powered privileged access monitoring."
    ),
    version="0.1.0",
)

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Project-P",
        "version": "0.1.0",
    }

@app.get("/")
def root():
    return {
        "message": "Project-P API is running.",
        "docs": "/docs",
        "health": "/health",
    }

@app.get("/monitor/events")
def get_okta_events(
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=100),
):
    try:
        client = OktaClient()
        events = client.get_system_logs(hours=hours, limit=limit)

        return {
            "source": "Okta System Log",
            "hours": hours,
            "count": len(events),
            "events": [
                {
                    "event_id": event.get("uuid"),
                    "event_type": event.get("eventType"),
                    "published": event.get("published"),
                    "outcome": (
                        event.get("outcome") or {}
                    ).get("result"),
                    "actor_type": (
                        event.get("actor") or {}
                    ).get("type"),
                }
                for event in events
            ],
        }

    except OktaClientError as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from None

@app.get("/monitor/findings")
def get_monitoring_findings(
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=100),
):
    try:
        client = OktaClient()
        events = client.get_system_logs(hours=hours, limit=limit)
        findings = prioritize_findings(analyze_events(events))

        return {
            "source": "Okta System Log",
            "events_analysed": len(events),
            "findings_count": len(findings),
            "findings": findings,
        }

    except OktaClientError as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from None

@app.get("/monitor/investigate")
def investigate_latest_finding(
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=100, ge=1, le=100),
):
    try:
        client = OktaClient()
        events = client.get_system_logs(hours=hours, limit=limit)
        findings = prioritize_findings(analyze_events(events))

        if not findings:
            return {
                "status": "no_findings",
                "message": (
                    "No events matched the current monitoring rules "
                    "in the retrieved window."
                ),
                "events_analysed": len(events),
            }

        finding = findings[0]
        report = investigate_finding(finding)

        return {
            "status": "investigated",
            "events_analysed": len(events),
            "finding": finding,
            "evidence": report["evidence"],
            "assessment": report["assessment"], 
        }

    except OktaClientError as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from None

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Investigation failed ({type(exc).__name__}).",
        ) from None