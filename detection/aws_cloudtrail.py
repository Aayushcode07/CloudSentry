
import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    PartialCredentialsError,
)


def fetch_cloudtrail_events(
    region: str = "ap-south-1",
    max_results: int = 20,
) -> list[dict]:
    """
    Fetch recent CloudTrail management events from AWS.

    Uses the standard AWS credential chain. Never place AWS credentials
    directly in this file. Requires valid credentials and read permissions.
    """
    if not 1 <= max_results <= 50:
        raise ValueError("max_results must be between 1 and 50.")

    try:
        client = boto3.client("cloudtrail", region_name=region)

        response = client.lookup_events(
            MaxResults=max_results,
        )

        events = []

        for item in response.get("Events", []):
            cloudtrail_event = item.get("CloudTrailEvent")

            if not cloudtrail_event:
                continue

            import json

            try:
                event = json.loads(cloudtrail_event)
            except json.JSONDecodeError:
                continue

            if isinstance(event, dict):
                events.append(event)

        return events

    except (NoCredentialsError, PartialCredentialsError) as exc:
        raise RuntimeError(
            "AWS credentials are not configured. "
            "Use sample-data events until AWS access is ready."
        ) from exc

    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "Unknown")
        raise RuntimeError(
            f"AWS CloudTrail request failed ({error_code}). "
            "Check credentials, region, and CloudTrail permissions."
        ) from exc

    except BotoCoreError as exc:
        raise RuntimeError(
            "Could not communicate with AWS. Check your connection and configuration."
        ) from exc


if __name__ == "__main__":
    try:
        events = fetch_cloudtrail_events()
        print(f"Fetched {len(events)} CloudTrail events from AWS.")

        for number, event in enumerate(events, start=1):
            print(
                f"{number}. {event.get('eventName', 'Unknown')} | "
                f"User: {event.get('userIdentity', {}).get('userName', 'Unknown')}"
            )

    except (RuntimeError, ValueError) as exc:
        print(f"Live CloudTrail unavailable: {exc}")
        print("Your local sample-data collector remains available.")
