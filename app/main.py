
import hashlib
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# --------------------------------------------------
# 1. PROJECT CONFIGURATION
# --------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from detection.rules import detect_threats
from detection.aws_cloudtrail import fetch_cloudtrail_events
from database.storage import (
    initialize_database,
    save_investigation,
    load_investigations,
)
from investigation.manager import (
    create_investigation,
    update_investigation,
)

DATA_FILE = PROJECT_ROOT / "sample-data" / "sample_events.json"

st.set_page_config(
    page_title="CloudSentry | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize the existing SQLite database.
initialize_database()

# --------------------------------------------------
# 2. CUSTOM DESIGN
# --------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');

    :root {
        --bg: #0a101b;
        --panel: #111b2a;
        --border: #26354a;
        --text: #e8eef7;
        --muted: #91a1b7;
        --teal: #48e0c1;
    }

    html, body, [class*="css"] {
        font-family: 'Manrope', sans-serif;
    }

    .stApp {
        background:
            radial-gradient(ellipse at 12% 0%, #142b3a 0%, transparent 38%),
            var(--bg);
        color: var(--text);
    }

    [data-testid="stHeader"] {
        background: rgba(10, 16, 27, 0.85);
    }

    [data-testid="stSidebar"] {
        background: #0c1421;
        border-right: 1px solid var(--border);
    }

    h1, h2, h3 {
        color: var(--text) !important;
        letter-spacing: -0.035em;
    }

    p, label {
        color: #d4deeb;
    }

    .cs-brand {
        font-size: 25px;
        font-weight: 800;
        color: #f0f6ff;
        padding: 8px 0;
    }

    .cs-kicker {
        color: var(--teal);
        font-family: 'DM Mono', monospace;
        font-size: 11px;
        letter-spacing: 2px;
        margin-bottom: 10px;
    }

    .cs-hero {
        padding: 28px;
        background: linear-gradient(115deg, #142b3b, #111d2d, #172438);
        border: 1px solid #2a4354;
        border-radius: 18px;
        margin-bottom: 24px;
    }

    .cs-hero h1 {
        font-size: 36px;
        font-weight: 800;
        margin-bottom: 8px;
    }

    .cs-hero p {
        color: #a9bbcf;
        font-size: 14px;
        line-height: 1.8;
    }

    [data-testid="stMetric"] {
        background: linear-gradient(145deg, #142033, #101927);
        border: 1px solid var(--border);
        padding: 17px;
        border-radius: 13px;
    }

    [data-testid="stMetricLabel"] {
        color: #9bacc1 !important;
    }

    [data-testid="stMetricValue"] {
        color: #f0f6ff !important;
        font-weight: 800;
    }

    .cs-panel {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 13px;
        padding: 18px;
        margin-bottom: 15px;
    }

    .stButton > button {
        background: #17423f;
        color: #eafffa;
        border: 1px solid #347a72;
        border-radius: 8px;
        font-weight: 700;
        min-height: 40px;
    }

    .stButton > button:hover {
        background: #20564f;
        color: white;
        border-color: var(--teal);
    }

    [data-testid="stDataFrame"] {
        border: 1px solid var(--border);
        border-radius: 10px;
    }

    hr {
        border-color: var(--border);
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# --------------------------------------------------
# 3. HELPER FUNCTIONS
# --------------------------------------------------
def load_sample_events():
    """Load local sample events."""
    if not DATA_FILE.exists():
        return []

    with open(DATA_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, dict):
        data = data.get("Records", [])

    return data if isinstance(data, list) else []


def normalize_aws_events(raw_events):
    """Normalize CloudTrail identity information."""
    normalized = []

    for event in raw_events:
        item = dict(event)
        identity = item.get("userIdentity", {})

        if isinstance(identity, dict):
            item["userName"] = (
                identity.get("userName")
                or identity.get("principalId")
                or identity.get("arn")
                or "Unknown"
            )

        item["eventName"] = item.get("eventName", "Unknown")
        item["sourceIPAddress"] = item.get(
            "sourceIPAddress", "Unknown"
        )

        normalized.append(item)

    return normalized


def event_dataframe(events):
    """Convert security events into a table."""
    return pd.DataFrame([
        {
            "Event": event.get("eventName", "Unknown"),
            "User": event.get("userName", "Unknown"),
            "Source IP": event.get("sourceIPAddress", "Unknown"),
            "Error": event.get("errorCode", "None"),
            "Region": event.get("awsRegion", "Unknown"),
        }
        for event in events
    ])


def evidence_hash(events):
    """Calculate a SHA-256 fingerprint of the loaded evidence."""
    content = json.dumps(
        events, sort_keys=True, default=str
    ).encode("utf-8")

    return hashlib.sha256(content).hexdigest()


def hero(title, description):
    """Display a consistent page header."""
    st.markdown(
        f"""
        <div class="cs-hero">
            <div class="cs-kicker">CLOUDSENTRY / SECURITY OPERATIONS</div>
            <h1>{title}</h1>
            <p>{description}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def get_severity_counts(alert_list):
    high = sum(
        1 for a in alert_list
        if str(a.get("severity", "")).lower() == "high"
    )
    medium = sum(
        1 for a in alert_list
        if str(a.get("severity", "")).lower() == "medium"
    )
    critical = sum(
        1 for a in alert_list
        if str(a.get("severity", "")).lower() == "critical"
    )
    return high, medium, critical


# --------------------------------------------------
# 4. SIDEBAR AND DATA SOURCE
# --------------------------------------------------
with st.sidebar:
    st.markdown(
        '<div class="cs-brand">🛡️ CloudSentry</div>',
        unsafe_allow_html=True,
    )
    st.caption("CLOUD SECURITY MONITORING")
    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Overview",
            "Event Explorer",
            "Threat Alerts",
            "Investigations",
            "Evidence Integrity",
        ],
    )

    st.divider()
    st.subheader("Event data source")

    data_source = st.selectbox(
        "Choose source",
        ["Local Sample Data", "AWS CloudTrail"],
    )

    aws_region = st.selectbox(
        "AWS Region",
        ["ap-south-1", "us-east-1", "us-west-2", "eu-west-1"],
        disabled=(data_source != "AWS CloudTrail"),
    )

    fetch_clicked = st.button(
        "Fetch AWS events",
        disabled=(data_source != "AWS CloudTrail"),
        use_container_width=True,
    )


# --------------------------------------------------
# 5. LOAD EVENTS
# --------------------------------------------------
if "cloudsentry_aws_events" not in st.session_state:
    st.session_state.cloudsentry_aws_events = None

if "cloudsentry_aws_error" not in st.session_state:
    st.session_state.cloudsentry_aws_error = None

if fetch_clicked:
    try:
        with st.spinner("Fetching CloudTrail event history..."):
            raw_events = fetch_cloudtrail_events(
                region=aws_region,
                max_results=20,
            )

        st.session_state.cloudsentry_aws_events = (
            normalize_aws_events(raw_events)
        )
        st.session_state.cloudsentry_aws_error = None

    except Exception as error:
        st.session_state.cloudsentry_aws_events = None
        st.session_state.cloudsentry_aws_error = str(error)

if data_source == "AWS CloudTrail":
    events = st.session_state.cloudsentry_aws_events

    if events is None:
        events = load_sample_events()
        st.info(
            "AWS events are unavailable. Showing local sample data. "
            "Configure AWS credentials and fetch events to use AWS data."
        )

    if st.session_state.cloudsentry_aws_error:
        st.warning(
            "AWS fetch failed: "
            + st.session_state.cloudsentry_aws_error
        )

    source_label = (
        "AWS CloudTrail"
        if st.session_state.cloudsentry_aws_events is not None
        else "Local Sample Data"
    )
else:
    events = load_sample_events()
    source_label = "Local Sample Data"

# --------------------------------------------------
# 6. THREAT DETECTION
# --------------------------------------------------
alerts = detect_threats(events)
high_alerts, medium_alerts, critical_alerts = get_severity_counts(
    alerts
)

# --------------------------------------------------
# 7. OVERVIEW
# --------------------------------------------------
if page == "Overview":
    hero(
        "Security Operations Center",
        "Monitor cloud events, identify suspicious activity, "
        "and preserve evidence for security investigations.",
    )

    st.markdown("### Security overview")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Events Loaded", len(events))
    col2.metric("Threat Alerts", len(alerts))
    col3.metric("High / Critical", high_alerts + critical_alerts)
    col4.metric("Medium Alerts", medium_alerts)

    left, right = st.columns([1.35, 1])

    with left:
        st.markdown("### Recent security events")
        df = event_dataframe(events)

        if not df.empty:
            st.dataframe(
                df.head(8),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No events are available.")

    with right:
        st.markdown("### Detection summary")

        if alerts:
            for alert in alerts[:6]:
                st.markdown(
                    f"""
                    <div class="cs-panel">
                        <b>{str(alert.get('severity', 'Unknown')).upper()}</b>
                        · {alert.get('eventName', 'Unknown')}<br>
                        <small>User: {alert.get('user', 'Unknown')}</small><br>
                        <small>{alert.get('reason', 'No description')}</small>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.success("No threats detected by the configured rules.")

    st.caption(
        f"Data source: {source_label} · "
        "AWS mode fetches event history on demand; "
        "it is not continuous real-time monitoring."
    )

# --------------------------------------------------
# 8. EVENT EXPLORER
# --------------------------------------------------
elif page == "Event Explorer":
    hero(
        "Event Explorer",
        "Search and review the security events available to CloudSentry.",
    )

    df = event_dataframe(events)

    if df.empty:
        st.info("No events are available.")
    else:
        search_text = st.text_input(
            "Search events",
            placeholder="Search by event, user, IP, or error...",
        )

        filtered_df = df.copy()

        if search_text:
            mask = filtered_df.astype(str).apply(
                lambda column: column.str.contains(
                    search_text,
                    case=False,
                    na=False,
                    regex=False,
                )
            ).any(axis=1)

            filtered_df = filtered_df[mask]

        st.caption(f"{len(filtered_df)} matching events")
        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Export events as CSV",
            data=filtered_df.to_csv(index=False).encode("utf-8"),
            file_name="cloudsentry_events.csv",
            mime="text/csv",
        )

# --------------------------------------------------
# 9. THREAT ALERTS
# --------------------------------------------------
elif page == "Threat Alerts":
    hero(
        "Threat Alerts",
        "Review suspicious activities detected by CloudSentry's "
        "configured security rules.",
    )

    if not alerts:
        st.success("No threats detected in the loaded events.")
    else:
        filter_severity = st.selectbox(
            "Filter by severity",
            ["All", "Critical", "High", "Medium", "Low"],
        )

        filtered_alerts = [
            alert for alert in alerts
            if filter_severity == "All"
            or str(alert.get("severity", "")).lower()
            == filter_severity.lower()
        ]

        st.metric("Matching Alerts", len(filtered_alerts))

        for index, alert in enumerate(filtered_alerts, start=1):
            severity = str(alert.get("severity", "Unknown")).upper()

            with st.expander(
                f"{index}. [{severity}] "
                f"{alert.get('eventName', 'Unknown')}",
                expanded=(severity in ["CRITICAL", "HIGH"]),
            ):
                st.write("**User:**", alert.get("user", "Unknown"))
                st.write(
                    "**Reason:**",
                    alert.get("reason", "No reason provided"),
                )
                st.write(
                    "**Event:**",
                    alert.get("eventName", "Unknown"),
                )

                if st.button(
                    "Create investigation from this alert",
                    key=f"create_incident_{index}",
                ):
                    incident = create_investigation(alert)
                    save_investigation(incident)
                    st.success(
                        f"Investigation {incident['id']} saved to SQLite."
                    )

# --------------------------------------------------
# 10. INVESTIGATIONS — PERSISTENT SQLITE STORAGE
# --------------------------------------------------
elif page == "Investigations":
    hero(
        "Investigation Workspace",
        "Create investigations from security alerts, add notes, "
        "and track their status. Records are stored in SQLite.",
    )

    # Create a new investigation from an existing detected alert.
    st.markdown("### Create an investigation")

    if alerts:
        alert_labels = [
            (
                f"{alert.get('eventName', 'Unknown')} | "
                f"{alert.get('user', 'Unknown')} | "
                f"{alert.get('severity', 'Medium')}"
            )
            for alert in alerts
        ]

        selected_index = st.selectbox(
            "Select the alert to investigate",
            range(len(alerts)),
            format_func=lambda i: alert_labels[i],
        )

        initial_notes = st.text_area(
            "Investigation notes",
            key="new_investigation_notes",
            placeholder="Describe what should be investigated...",
        )

        if st.button("Create and save investigation"):
            incident = create_investigation(alerts[selected_index])
            incident["notes"] = initial_notes.strip()

            try:
                save_investigation(incident)
                st.success(
                    f"Investigation {incident['id']} saved permanently."
                )
                st.rerun()
            except Exception as error:
                st.error(f"Could not save investigation: {error}")
    else:
        st.info(
            "No alerts are available to investigate. "
            "Load events that trigger your detection rules first."
        )

    st.divider()
    st.markdown("### Saved investigation records")

    try:
        investigations = load_investigations()
    except Exception as error:
        investigations = []
        st.error(f"Could not load investigations: {error}")

    if not investigations:
        st.info(
            "No saved investigations yet. Create one above or "
            "create one from the Threat Alerts page."
        )
    else:
        st.caption(f"{len(investigations)} investigation(s) stored in SQLite")

        for incident in investigations:
            incident_id = incident["id"]

            with st.expander(
                f"{incident['eventName']} · {incident['severity']} · "
                f"{incident['status']} · {incident_id}"
            ):
                st.write("**Event:**", incident["eventName"])
                st.write("**User:**", incident["user"])
                st.write("**Reason:**", incident["reason"])
                st.write("**Created:**", incident["created_at"])

                status_options = ["Open", "In Progress", "Resolved"]
                current_status = incident.get("status", "Open")

                if current_status not in status_options:
                    current_status = "Open"

                status_index = status_options.index(current_status)

                new_status = st.selectbox(
                    "Investigation status",
                    status_options,
                    index=status_index,
                    key=f"status_{incident_id}",
                )

                new_notes = st.text_area(
                    "Investigation notes",
                    value=incident.get("notes", ""),
                    key=f"notes_{incident_id}",
                )

                if st.button(
                    "Save changes",
                    key=f"save_{incident_id}",
                ):
                    try:
                        updated_incident = update_investigation(
                            incident,
                            status=new_status,
                            notes=new_notes,
                        )
                        save_investigation(updated_incident)
                        st.success("Investigation changes saved to SQLite.")
                        st.rerun()
                    except Exception as error:
                        st.error(f"Could not update investigation: {error}")

    st.caption(
        "Investigations are saved in cloudsentry.db. "
        "They should remain available after a browser refresh or app restart."
    )

# --------------------------------------------------
# 11. EVIDENCE INTEGRITY
# --------------------------------------------------
elif page == "Evidence Integrity":
    hero(
        "Evidence Integrity",
        "Generate a SHA-256 fingerprint to help verify whether "
        "the currently loaded event evidence has changed.",
    )

    fingerprint = evidence_hash(events)

    st.markdown("### Evidence fingerprint")
    st.code(fingerprint, language="text")

    st.caption(
        "Algorithm: SHA-256 · Input: normalized JSON representation "
        "of the currently loaded event list."
    )

    if st.button("Recalculate fingerprint"):
        st.rerun()

    st.markdown("### Evidence details")

    col1, col2 = st.columns(2)
    col1.metric("Events Included", len(events))
    col2.metric("Fingerprint Length", len(fingerprint))

    st.warning(
        "A matching fingerprint can help detect changes to the same "
        "serialized evidence. It does not independently prove when, "
        "where, or by whom the evidence was collected."
    )

# --------------------------------------------------
# 12. FOOTER
# --------------------------------------------------
st.divider()

st.caption(
    f"CloudSentry Security Operations · Data source: {source_label} · "
    "Rule-based detection prototype"
)
