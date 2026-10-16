import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# Allow imports from the project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from detection.rules import detect_threats

DATA_FILE = PROJECT_ROOT / "sample-data" / "sample_events.json"

st.set_page_config(
    page_title="CloudSentry",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ CloudSentry")
st.subheader("Cloud Security Monitoring Dashboard")
st.write("Monitor cloud activity and investigate suspicious events.")


def load_events():
    """Load sample security events from a JSON file."""
    with DATA_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError("The JSON file must contain a list of events.")

    return data


try:
    events = load_events()
    alerts = detect_threats(events)
except (OSError, json.JSONDecodeError, ValueError) as error:
    st.error(f"Unable to load security events: {error}")
    st.stop()

# Prepare activity table
event_rows = [
    {
        "Event": event.get("eventName", "Unknown"),
        "User": event.get("userName", "Unknown"),
        "Source IP": event.get("sourceIPAddress", "Unknown"),
        "Result": "Failed" if event.get("errorCode") else "Recorded",
    }
    for event in events
]

events_df = pd.DataFrame(
    event_rows,
    columns=["Event", "User", "Source IP", "Result"],
)

alerts_df = pd.DataFrame(
    alerts,
    columns=["eventName", "severity", "reason", "user"],
)

high_count = sum(
    alert["severity"] == "High" for alert in alerts
)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", len(events))
col2.metric("Active Alerts", len(alerts))
col3.metric("High Severity", high_count)
col4.metric("Investigations", 0)

st.divider()
st.header("Security Activity Explorer")

search = st.text_input("Search events or users")

filtered_events = events_df

if search:
    mask = events_df.astype(str).apply(
        lambda column: column.str.contains(
            search, case=False, na=False
        )
    ).any(axis=1)

    filtered_events = events_df[mask]

st.dataframe(filtered_events, use_container_width=True)

st.header("Threat Detection Alerts")

if alerts_df.empty:
    st.success("No suspicious events detected.")
else:
    st.dataframe(alerts_df, use_container_width=True)

st.caption(
    "Prototype using sample JSON events. "
    "Live AWS integration is not enabled yet."
)