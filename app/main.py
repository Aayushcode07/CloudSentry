import hashlib
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# Project path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from detection.rules import detect_threats
from investigation.manager import (
    create_investigation,
    update_investigation,
)
from database.storage import (
    initialize_database,
    save_investigation,
    load_investigations,
)

DATA_FILE = PROJECT_ROOT / "sample-data" / "sample_events.json"

# Page settings
st.set_page_config(
    page_title="CloudSentry",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ CloudSentry")
st.subheader("Cloud Security Monitoring Dashboard")
st.write("Monitor cloud activity and investigate suspicious events.")

# Initialize persistent database
initialize_database()

# Load investigations from SQLite
if "investigations" not in st.session_state:
    st.session_state.investigations = load_investigations()

# Load security events
def load_events():
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

# Dashboard metrics
open_count = sum(
    item["status"] == "Open"
    for item in st.session_state.investigations
)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", len(events))
col2.metric("Active Alerts", len(alerts))
col3.metric("High Severity", high_count)
col4.metric("Open Investigations", open_count)

# Security Activity Explorer
st.divider()
st.header("🔎 Security Activity Explorer")

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

# Threat Detection Alerts
st.divider()
st.header("🚨 Threat Detection Alerts")

if alerts_df.empty:
    st.success("No suspicious events detected.")
else:
    st.dataframe(alerts_df, use_container_width=True)

# Incident Investigation
st.divider()
st.header("🕵️ Incident Investigation")

st.write(
    "Create investigations from detected alerts, track their status, "
    "and save investigation notes permanently."
)

if not alerts:
    st.info("There are no detected alerts to investigate.")
else:
    for index, alert in enumerate(alerts):
        st.subheader(
            f"{alert.get('eventName', 'Unknown')} "
            f"— {alert.get('severity', 'Unknown')}"
        )
        st.write("**User:**", alert.get("user", "Unknown"))
        st.write("**Reason:**", alert.get("reason", "Not provided"))

        already_created = any(
            item.get("eventName") == alert.get("eventName")
            and item.get("user") == alert.get("user", "Unknown")
            and item.get("reason") == alert.get("reason")
            for item in st.session_state.investigations
        )

        if not already_created:
            if st.button(
                "Create Investigation",
                key=f"create_incident_{index}",
            ):
                incident = create_investigation(alert)

                # Save permanently to SQLite
                save_investigation(incident)

                # Update current dashboard session
                st.session_state.investigations.append(incident)

                st.success("Investigation saved to the database.")
                st.rerun()
        else:
            st.caption("An investigation already exists for this alert.")

        st.divider()

# Manage existing investigations
st.subheader("📋 Investigation Records")

if not st.session_state.investigations:
    st.info("No investigations created yet.")
else:
    for incident in st.session_state.investigations:
        with st.expander(
            f"{incident['id']} — {incident['eventName']} "
            f"({incident['status']})"
        ):
            st.write("**Severity:**", incident["severity"])
            st.write("**User:**", incident["user"])
            st.write("**Reason:**", incident["reason"])
            st.write("**Created:**", incident["created_at"])

            with st.form(key=f"form_{incident['id']}"):
                new_status = st.selectbox(
                    "Investigation Status",
                    ["Open", "In Progress", "Resolved"],
                    index=[
                        "Open",
                        "In Progress",
                        "Resolved",
                    ].index(incident["status"]),
                )

                new_notes = st.text_area(
                    "Investigation Notes",
                    value=incident["notes"],
                    placeholder="Describe your findings and actions...",
                )

                save = st.form_submit_button("Save Investigation")

                if save:
                    updated = update_investigation(
                        incident,
                        status=new_status,
                        notes=new_notes,
                    )

                    # Persist changes before updating the session
                    save_investigation(updated)

                    incident_index = st.session_state.investigations.index(
                        incident
                    )
                    st.session_state.investigations[incident_index] = updated

                    st.success("Investigation saved permanently.")
                    st.rerun()

# Evidence Integrity
st.divider()
st.header("🔐 Evidence Integrity Verification")

st.write(
    "Upload a file to calculate its SHA-256 fingerprint. "
    "Compare it with a trusted fingerprint to check whether "
    "the file contents match."
)

uploaded_file = st.file_uploader(
    "Choose an evidence file",
    key="evidence_file",
)

if uploaded_file is not None:
    file_bytes = uploaded_file.getvalue()
    current_hash = hashlib.sha256(file_bytes).hexdigest()

    st.write("**File name:**", uploaded_file.name)
    st.write("**SHA-256 fingerprint:**")
    st.code(current_hash)

    expected_hash = st.text_input(
        "Enter the trusted SHA-256 fingerprint",
        placeholder="Paste the original fingerprint here",
    )

    if st.button("Verify Evidence Integrity"):
        if not expected_hash.strip():
            st.warning("Please enter the trusted fingerprint.")
        elif current_hash.lower() == expected_hash.strip().lower():
            st.success(
                "Fingerprint matches. The uploaded file matches "
                "the supplied fingerprint."
            )
        else:
            st.error(
                "Fingerprint mismatch. The uploaded file does not "
                "match the supplied fingerprint."
            )

# Prototype status
st.divider()
st.caption(
    "CloudSentry prototype using sample JSON events and SQLite "
    "for persistent investigation records. Live AWS integration "
    "is not enabled yet."
)