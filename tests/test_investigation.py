from investigation.manager import (
    create_investigation,
    update_investigation,
)


def test_create_investigation_from_alert():
    alert = {
        "eventName": "ConsoleLogin",
        "severity": "High",
        "reason": "Failed console login attempt detected",
        "user": "admin",
    }

    incident = create_investigation(alert)

    assert incident["eventName"] == "ConsoleLogin"
    assert incident["severity"] == "High"
    assert incident["user"] == "admin"
    assert incident["status"] == "Open"
    assert incident["notes"] == ""
    assert incident["id"].startswith("INC-")


def test_update_investigation_status_and_notes():
    incident = create_investigation({
        "eventName": "CreateAccessKey",
        "severity": "Medium",
        "reason": "Access key creation requires review",
        "user": "developer",
    })

    updated = update_investigation(
        incident,
        status="In Progress",
        notes="Reviewing this event.",
    )

    assert updated["status"] == "In Progress"
    assert updated["notes"] == "Reviewing this event."
    assert incident["status"] == "Open"


def test_invalid_investigation_status_is_rejected():
    incident = create_investigation({
        "eventName": "ConsoleLogin",
        "severity": "High",
        "user": "admin",
    })

    try:
        update_investigation(incident, status="Unknown")
        assert False, "Invalid status should raise ValueError"
    except ValueError:
        pass