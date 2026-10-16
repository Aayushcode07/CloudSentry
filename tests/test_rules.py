from detection.rules import detect_threats


def test_failed_login_detection():
    events = [
        {
            "eventName": "ConsoleLogin",
            "errorCode": "FailedAuthentication",
            "userName": "admin"
        }
    ]

    alerts = detect_threats(events)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "High"
    assert alerts[0]["user"] == "admin"


def test_access_key_creation_detection():
    events = [
        {
            "eventName": "CreateAccessKey",
            "userName": "developer"
        }
    ]

    alerts = detect_threats(events)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "Medium"


def test_normal_event_creates_no_alert():
    events = [
        {
            "eventName": "DescribeInstances",
            "userName": "developer"
        }
    ]

    alerts = detect_threats(events)

    assert alerts == []