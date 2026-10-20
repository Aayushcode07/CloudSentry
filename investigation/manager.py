from datetime import datetime, timezone


def create_investigation(alert):
    """Create an investigation record from a detected security alert."""
    return {
        "id": f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
        "eventName": alert.get("eventName", "Unknown"),
        "severity": alert.get("severity", "Medium"),
        "reason": alert.get("reason", "No reason provided"),
        "user": alert.get("user", "Unknown"),
        "status": "Open",
        "notes": "",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def update_investigation(investigation, status=None, notes=None):
    """Update the status or notes of an investigation."""
    updated = investigation.copy()

    if status is not None:
        allowed_statuses = {"Open", "In Progress", "Resolved"}

        if status not in allowed_statuses:
            raise ValueError(
                f"Status must be one of: {', '.join(sorted(allowed_statuses))}"
            )

        updated["status"] = status

    if notes is not None:
        updated["notes"] = notes

    return updated