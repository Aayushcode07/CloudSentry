def detect_threats(events):
    """
    Detect suspicious security events from log records.
    """

    alerts = []

    for event in events:
        event_name = str(event.get("eventName", ""))
        error_code = str(event.get("errorCode", ""))

        # Detect failed authentication attempts
        if (
            event_name == "ConsoleLogin"
            and error_code
            in ["FailedAuthentication", "UnauthorizedOperation"]
        ):
            alerts.append({
                "eventName": event_name,
                "severity": "High",
                "reason": "Failed console login attempt detected",
                "user": event.get("userName", "Unknown")
            })

        # Detect IAM access-key creation
        if event_name == "CreateAccessKey":
            alerts.append({
                "eventName": event_name,
                "severity": "Medium",
                "reason": "IAM access key creation requires review",
                "user": event.get("userName", "Unknown")
            })

    return alerts