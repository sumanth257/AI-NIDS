
import streamlit as st
import pandas as pd
import os
import time
import plotly.express as px

# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="AI-NIDS | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# CUSTOM CYBERSECURITY THEME
# ==========================================

st.markdown("""
<style>

.stApp {
    background-color: #0b1120;
    color: #e2e8f0;
}

[data-testid="stHeader"] {
    background-color: #0b1120;
}

[data-testid="stSidebar"] {
    background-color: #111827;
    border-right: 1px solid #263449;
}

[data-testid="stSidebar"] * {
    color: #cbd5e1;
}

h1 {
    color: #38bdf8 !important;
    font-weight: 800 !important;
}

h2, h3 {
    color: #e2e8f0 !important;
}

p {
    color: #94a3b8;
}

div[data-testid="stMetric"] {
    background-color: #151f32;
    border: 1px solid #27364d;
    padding: 20px;
    border-radius: 12px;
    box-shadow: 0px 4px 15px rgba(0,0,0,0.25);
}

div[data-testid="stMetricLabel"] {
    color: #94a3b8;
    font-size: 14px;
}

div[data-testid="stMetricValue"] {
    color: #38bdf8;
    font-size: 30px;
    font-weight: bold;
}

.stTabs [data-baseweb="tab"] {
    color: #94a3b8;
}

.stTabs [aria-selected="true"] {
    color: #38bdf8 !important;
    border-bottom-color: #38bdf8 !important;
}

div[data-testid="stDataFrame"] {
    border: 1px solid #263449;
    border-radius: 10px;
}

hr {
    border-color: #263449;
}

.status-online {
    color: #22c55e;
    font-weight: bold;
}

</style>
""", unsafe_allow_html=True)

# ==========================================
# SIDEBAR
# ==========================================

st.sidebar.markdown("# 🛡️ AI-NIDS")
st.sidebar.markdown("### Security Operations Center")

st.sidebar.markdown(
    '<p class="status-online">● SYSTEM MONITORING ACTIVE</p>',
    unsafe_allow_html=True
)

st.sidebar.divider()

refresh = st.sidebar.toggle("Live Auto Refresh", value=True)

refresh_interval = st.sidebar.selectbox(
    "Refresh Interval",
    [3, 5, 10, 15],
    index=1
)

st.sidebar.divider()

page = st.sidebar.radio(
    "NAVIGATION",
    [
        "Overview",
        "Security Alerts",
        "Network Traffic",
        "Analytics"
    ]
)

st.sidebar.divider()

st.sidebar.caption("AI-NIDS | Cybersecurity Lab")
st.sidebar.caption("Powered by Python + Scapy + ML")

# ==========================================
# HEADER
# ==========================================

st.markdown("# 🛡️ AI NETWORK INTRUSION DETECTION")

st.markdown(
    "### Security Monitoring & Threat Intelligence"
)

st.markdown(
    '<p class="status-online">● LIVE PACKET MONITORING</p>',
    unsafe_allow_html=True
)

st.divider()

# ==========================================
# LOAD DATA
# ==========================================

FILE = "alerts.csv"

if not os.path.exists(FILE):
    st.error("alerts.csv not found. Start the NIDS detector first.")
    st.stop()

try:
    df = pd.read_csv(FILE)

except Exception as error:
    st.error(f"Unable to read alerts.csv: {error}")
    st.stop()

if df.empty:
    st.warning("Waiting for network traffic...")
    st.stop()

required_columns = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "packet_size",
    "tcp_flags",
    "ai_result",
    "rule_result",
    "detection_result"
]

if not all(column in df.columns for column in required_columns):
    st.error("CSV structure mismatch. Please check alerts.csv.")
    st.stop()

# ==========================================
# CALCULATE METRICS
# ==========================================

total = len(df)

normal = (
    df["detection_result"] == "NORMAL"
).sum()

anomalous = (
    df["detection_result"] == "ANOMALOUS"
).sum()

ai_alerts = (
    df["ai_result"] == "ANOMALOUS"
).sum()

rule_alerts = (
    df["rule_result"] == "PORT_SCAN"
).sum()

scan_incidents = df[
    df["rule_result"] == "PORT_SCAN"
].groupby(
    ["source_ip", "destination_ip"]
).ngroups

anomaly_rate = (
    anomalous / total * 100
    if total else 0
)

# ==========================================
# OVERVIEW PAGE
# ==========================================

if page == "Overview":

    st.markdown("## 📊 Security Overview")

    # First row of metric cards
    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "TOTAL PACKETS",
        f"{total:,}"
    )

    c2.metric(
        "NORMAL TRAFFIC",
        f"{normal:,}"
    )

    c3.metric(
        "AI ANOMALIES",
        f"{ai_alerts:,}"
    )

    c4.metric(
        "PORT SCAN INCIDENTS",
        f"{scan_incidents:,}"
    )

    # Second row
    c5, c6, c7, c8 = st.columns(4)

    c5.metric(
        "RULE ALERT PACKETS",
        f"{rule_alerts:,}"
    )

    c6.metric(
        "ANOMALOUS PACKETS",
        f"{anomalous:,}"
    )

    c7.metric(
        "ANOMALY RATE",
        f"{anomaly_rate:.2f}%"
    )

    c8.metric(
        "PROTOCOL TYPES",
        df["protocol"].nunique()
    )

    st.divider()

    # Charts
    left, right = st.columns(2)

    with left:

        st.markdown("### 🎯 Detection Distribution")

        detection_counts = (
            df["detection_result"]
            .value_counts()
            .reset_index()
        )

        detection_counts.columns = [
            "Detection",
            "Count"
        ]

        fig = px.pie(
            detection_counts,
            names="Detection",
            values="Count",
            hole=0.65,
            color="Detection",
            color_discrete_map={
                "NORMAL": "#22c55e",
                "ANOMALOUS": "#ef4444"
            }
        )

        fig.update_layout(
            paper_bgcolor="#0b1120",
            plot_bgcolor="#0b1120",
            font_color="#e2e8f0",
            legend_title="Traffic Status"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    with right:

        st.markdown("### 🌐 Protocol Distribution")

        protocol_counts = (
            df["protocol"]
            .value_counts()
            .reset_index()
        )

        protocol_counts.columns = [
            "Protocol",
            "Count"
        ]

        fig = px.bar(
            protocol_counts,
            x="Protocol",
            y="Count",
            color="Protocol",
            color_discrete_sequence=[
                "#38bdf8",
                "#8b5cf6",
                "#22c55e",
                "#f59e0b"
            ]
        )

        fig.update_layout(
            paper_bgcolor="#0b1120",
            plot_bgcolor="#0b1120",
            font_color="#e2e8f0",
            showlegend=False
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    st.divider()

    # Top IPs
    st.markdown("### 🖥️ Top Traffic Sources")

    top_sources = (
        df["source_ip"]
        .value_counts()
        .head(10)
        .reset_index()
    )

    top_sources.columns = [
        "Source IP",
        "Packets"
    ]

    fig = px.bar(
        top_sources,
        x="Packets",
        y="Source IP",
        orientation="h",
        color="Packets",
        color_continuous_scale="Blues"
    )

    fig.update_layout(
        paper_bgcolor="#0b1120",
        plot_bgcolor="#0b1120",
        font_color="#e2e8f0",
        yaxis=dict(autorange="reversed")
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    # Recent alerts
    st.markdown("### 🚨 Recent Security Alerts")

    recent_alerts = df[
        df["detection_result"] == "ANOMALOUS"
    ].tail(10).iloc[::-1]

    if not recent_alerts.empty:

        st.dataframe(
            recent_alerts,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.success("No anomalous packets detected.")

# ==========================================
# SECURITY ALERTS PAGE
# ==========================================

elif page == "Security Alerts":

    st.markdown("## 🚨 Security Alert Center")

    alerts = df[
        (df["detection_result"] == "ANOMALOUS") |
        (df["rule_result"] == "PORT_SCAN")
    ].copy()

    if not alerts.empty:

        alerts["severity"] = alerts.apply(
            lambda row:
                "HIGH"
                if row["rule_result"] == "PORT_SCAN"
                else "MEDIUM",
            axis=1
        )

        severity_filter = st.multiselect(
            "Filter by Severity",
            ["HIGH", "MEDIUM"],
            default=["HIGH", "MEDIUM"]
        )

        filtered = alerts[
            alerts["severity"].isin(severity_filter)
        ]

        st.metric(
            "Total Security Alert Packets",
            len(alerts)
        )

        st.dataframe(
            filtered.tail(100).iloc[::-1],
            use_container_width=True,
            hide_index=True
        )

        st.download_button(
            "📥 Download Security Alerts CSV",
            data=filtered.to_csv(index=False),
            file_name="security_alerts.csv",
            mime="text/csv"
        )

    else:
        st.success("No security alerts detected.")

# ==========================================
# NETWORK TRAFFIC PAGE
# ==========================================

elif page == "Network Traffic":

    st.markdown("## 🌐 Network Traffic Explorer")

    col1, col2 = st.columns(2)

    with col1:

        protocol_filter = st.multiselect(
            "Filter Protocol",
            df["protocol"].unique(),
            default=list(df["protocol"].unique())
        )

    with col2:

        result_filter = st.multiselect(
            "Filter Detection Result",
            df["detection_result"].unique(),
            default=list(df["detection_result"].unique())
        )

    filtered_df = df[
        df["protocol"].isin(protocol_filter) &
        df["detection_result"].isin(result_filter)
    ]

    st.metric(
        "Filtered Packets",
        len(filtered_df)
    )

    st.dataframe(
        filtered_df.tail(200).iloc[::-1],
        use_container_width=True,
        hide_index=True
    )

    st.download_button(
        "📥 Export Network Traffic",
        data=filtered_df.to_csv(index=False),
        file_name="network_traffic_export.csv",
        mime="text/csv"
    )

# ==========================================
# ANALYTICS PAGE
# ==========================================

elif page == "Analytics":

    st.markdown("## 📈 Network Security Analytics")

    # AI vs rule comparison
    comparison = pd.DataFrame({
        "Detection Engine": [
            "Isolation Forest AI",
            "Rule-Based Engine"
        ],
        "Alert Packets": [
            ai_alerts,
            rule_alerts
        ]
    })

    fig = px.bar(
        comparison,
        x="Detection Engine",
        y="Alert Packets",
        color="Detection Engine",
        color_discrete_sequence=[
            "#8b5cf6",
            "#ef4444"
        ]
    )

    fig.update_layout(
        paper_bgcolor="#0b1120",
        plot_bgcolor="#0b1120",
        font_color="#e2e8f0",
        showlegend=False
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    # Packet size analysis
    st.markdown("### 📦 Packet Size Distribution")

    fig = px.histogram(
        df,
        x="packet_size",
        color="detection_result",
        color_discrete_map={
            "NORMAL": "#22c55e",
            "ANOMALOUS": "#ef4444"
        },
        nbins=30
    )

    fig.update_layout(
        paper_bgcolor="#0b1120",
        plot_bgcolor="#0b1120",
        font_color="#e2e8f0"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    # Traffic by time
    st.markdown("### ⏱️ Traffic Over Time")

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    timeline = (
        df.dropna(subset=["timestamp"])
        .set_index("timestamp")
        .resample("1min")
        .size()
        .reset_index(name="Packets")
    )

    if not timeline.empty:

        fig = px.line(
            timeline,
            x="timestamp",
            y="Packets",
            markers=True
        )

        fig.update_traces(
            line_color="#38bdf8"
        )

        fig.update_layout(
            paper_bgcolor="#0b1120",
            plot_bgcolor="#0b1120",
            font_color="#e2e8f0"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

# ==========================================
# FOOTER
# ==========================================

st.divider()

st.markdown(
    "<center style='color:#64748b'>"
    "AI-NIDS | Network Security Monitoring Lab | "
    "Python • Scapy • Scikit-learn • Streamlit"
    "</center>",
    unsafe_allow_html=True
)

# ==========================================
# AUTO REFRESH
# ==========================================

if refresh:
    time.sleep(refresh_interval)
    st.rerun()

