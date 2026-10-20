
import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detection.rules import detect_threats
from detection.aws_cloudtrail import fetch_cloudtrail_events


def load_cloudtrail_events(file_path: str | Path) -> list[dict[str, Any]]:
    """Load events from a JSON list or CloudTrail Records object."""
    path = Path(file_path)

    if not path.is_absolute():
        path = Path.cwd() / path

    if not path.is_file():
        raise FileNotFoundError(f"Events file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc

    if isinstance(data, list):
        events = data
    elif isinstance(data, dict) and isinstance(data.get("Records"), list):
        events = data["Records"]
    else:
        raise ValueError(
            "Expected a JSON list or an object containing a Records list."
        )

    if not all(isinstance(event, dict) for event in events):
        raise ValueError("Every event must be a JSON object.")

    return events


def analyze_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze events using CloudSentry's existing detection rules."""
    alerts = detect_threats(events)

    return {
        "event_count": len(events),
        "alert_count": len(alerts),
        "events": events,
        "alerts": alerts,
    }


def analyze_cloudtrail_file(file_path: str | Path) -> dict[str, Any]:
    """Analyze events loaded from a local JSON file."""
    return analyze_events(load_cloudtrail_events(file_path))


def print_results(result: dict[str, Any], source: str) -> None:
    print(f"Source: {source}")
    print(f"Events loaded: {result['event_count']}")
    print(f"Threat alerts: {result['alert_count']}")
    print("\nDetected alerts:")

    if not result["alerts"]:
        print("No alerts detected.")
        return

    for number, alert in enumerate(result["alerts"], start=1):
        print(
            f"{number}. [{alert['severity']}] "
            f"{alert['eventName']} | "
            f"User: {alert['user']} | "
            f"{alert['reason']}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze local or live AWS CloudTrail events with CloudSentry."
    )

    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument(
        "--aws",
        action="store_true",
        help="Fetch recent management events from AWS CloudTrail.",
    )
    source_group.add_argument(
        "--file",
        default=None,
        help="Path to a local JSON event file.",
    )

    parser.add_argument(
        "--region",
        default="ap-south-1",
        help="AWS region for live mode (default: ap-south-1).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum AWS events to fetch, from 1 to 50 (default: 20).",
    )

    args = parser.parse_args()

    try:
        if args.aws:
            events = fetch_cloudtrail_events(
                region=args.region,
                max_results=args.limit,
            )
            result = analyze_events(events)
            print_results(result, f"AWS CloudTrail ({args.region})")
        else:
            file_path = args.file or str(
                PROJECT_ROOT / "sample-data" / "sample_events.json"
            )
            result = analyze_cloudtrail_file(file_path)
            print_results(result, f"Local file: {file_path}")

        return 0

    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"Collector error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
