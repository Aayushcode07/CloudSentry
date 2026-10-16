\# CloudSentry



\*\*Cloud Security Monitoring and Explainable Threat Detection Dashboard\*\*



CloudSentry is a cloud security monitoring project designed to analyze security activity logs, detect suspicious events using transparent rules, and display alerts through an interactive dashboard.



\## Objectives



\- Analyze cloud security activity logs.

\- Detect suspicious activities using configurable rules.

\- Generate severity-based security alerts.

\- Explore events and investigate potential incidents.

\- Verify evidence integrity using SHA-256 hashing.

\- Integrate AWS CloudTrail, CloudWatch, and S3 in later development stages.



\## Technology Stack



\- Python

\- Streamlit

\- Pandas

\- Plotly

\- MySQL

\- AWS

\- Pytest



\## Project Structure



```text

CloudSentry/

├── app/

│   ├── pages/

│   ├── \_\_init\_\_.py

│   └── main.py

├── database/

├── detection/

│   ├── \_\_init\_\_.py

│   └── rules.py

├── docs/

├── sample-data/

├── scripts/

├── tests/

├── .gitignore

├── README.md

└── requirements.txt

```



\## Development Plan



1\. Build the local dashboard.

2\. Implement security log processing and detection rules.

3\. Add alerts and investigation features.

4\. Implement SHA-256 evidence integrity verification.

5\. Add optional AWS integration.

6\. Test and document the application.



\## Project Status



Initial setup in progress.



\## Disclaimer



CloudSentry is an educational project. Test it using authorized systems and sample security logs.

