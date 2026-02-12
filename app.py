import streamlit as st
import pandas as pd
import altair as alt
from pathlib import Path
from datetime import datetime

# Import backend modules
from core.ingest import load_logs
from core.ai_detection import detect_ml_anomalies
from core.detect_exfil import detect_data_exfiltration
from core.detect_net import detect_port_scan, detect_suspicious_ops
from core.detect_auth import detect_brute_force
from core.correlation import correlate_alerts

# Page Config
st.set_page_config(
    page_title="Threat Detection Platform",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS
st.markdown("""
    <style>
        .metric-card {
            background-color: #1E1E1E;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        .stAlert {
            border-radius: 5px;
        }
    </style>
""", unsafe_allow_html=True)

def main():
    st.title("🛡️ Intelligent Threat Detection Platform")
    st.markdown("### AI-Powered Network Security Analysis")

    # --- Sidebar: Configuration ---
    st.sidebar.header("Configuration")
    
    # file selector
    data_dir = Path("data")
    if not data_dir.exists():
        st.sidebar.error("Data directory not found!")
        return

    log_files = list(data_dir.glob("*.csv"))
    if not log_files:
        st.sidebar.warning("No CSV log files found in data/ directory.")
        return

    selected_file = st.sidebar.selectbox(
        "Select Network Log File",
        log_files,
        format_func=lambda x: x.name
    )

    run_btn = st.sidebar.button("Run Threat Analysis", type="primary")

    # --- Main Content ---
    if run_btn and selected_file:
        with st.spinner(f"Analyzing {selected_file.name}..."):
            try:
                # 1. Ingest
                logs = load_logs(selected_file)
                st.toast(f"Loaded {len(logs)} logs", icon="✅")
                
                # 2. Detect
                all_alerts = []
                
                # AI
                ai_alerts = detect_ml_anomalies(logs)
                all_alerts.extend(ai_alerts)
                
                # Exfil
                exfil_alerts = detect_data_exfiltration(logs)
                all_alerts.extend(exfil_alerts)
                
                # Network
                net_alerts = detect_port_scan(logs) + detect_suspicious_ops(logs)
                all_alerts.extend(net_alerts)
                
                # Auth
                auth_alerts = detect_brute_force(logs) # type: ignore
                all_alerts.extend(auth_alerts)
                
                # 3. Correlate
                incidents = correlate_alerts(all_alerts)
                
                # --- Dashboard Layout ---
                
                # Metrics Row
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Total Logs Processed", len(logs))
                col2.metric("Total Alerts", len(all_alerts), delta_color="inverse")
                col3.metric("Correlated Incidents", len(incidents), delta_color="inverse")
                col4.metric("Unique IPs Monitored", len(set(l.src_ip for l in logs)))
                
                st.divider()

                # Tabbed View
                tab1, tab2, tab3 = st.tabs(["🔴 Incidents", "⚠️ All Alerts", "📊 Visualizations"])
                
                with tab1:
                    st.subheader("Active Incidents")
                    if incidents:
                        for inc in incidents:
                            with st.expander(f"Incident {inc.id} | IP: {inc.primary_ip} | Severity: {inc.status}"):
                                st.write(f"**Status:** {inc.status}")
                                st.write(f"**Associated Alerts:** {len(inc.alerts)}")
                                
                                # Show alerts for this incident
                                inc_df = pd.DataFrame([vars(a) for a in inc.alerts])
                                st.dataframe(inc_df, use_container_width=True)
                    else:
                        st.success("No active incidents detected.")

                with tab2:
                    st.subheader("Detailed Alert Log")
                    if all_alerts:
                        # Convert alerts to DataFrame for filtering
                        alerts_df = pd.DataFrame([vars(a) for a in all_alerts])
                        
                        # Interactive filters
                        alert_types = st.multiselect("Filter by Type", alerts_df['alert_type'].unique())
                        if alert_types:
                            alerts_df = alerts_df[alerts_df['alert_type'].isin(alert_types)]
                            
                        st.dataframe(
                            alerts_df,
                            column_config={
                                "timestamp": st.column_config.DatetimeColumn("Time", format="D MMM HH:mm:ss"),
                                "severity": st.column_config.TextColumn("Severity"),
                            },
                            use_container_width=True
                        )
                    else:
                        st.info("No alerts generated.")

                with tab3:
                    st.subheader("Threat Analytics")
                    if all_alerts:
                        alerts_df = pd.DataFrame([vars(a) for a in all_alerts])
                        
                        # 1. Alerts over time
                        chart_time = alt.Chart(alerts_df).mark_bar().encode(
                            x=alt.X('timestamp', title='Time'),
                            y=alt.Y('count()', title='Alert Count'),
                            color='severity'
                        ).properties(title="Alert Frequency Over Time")
                        st.altair_chart(chart_time, use_container_width=True)
                        
                        # 2. Top Attacking IPs
                        chart_ips = alt.Chart(alerts_df).mark_bar().encode(
                            y=alt.Y('src_ip', sort='-x', title='Source IP'),
                            x=alt.X('count()', title='Alert Count'),
                            color='alert_type'
                        ).properties(title="Top Source IPs by Alert Count")
                        st.altair_chart(chart_ips, use_container_width=True)
                    else:
                        st.info("Not enough data for visualization.")

            except Exception as e:
                st.error(f"An error occurred during analysis: {e}")
                st.exception(e)

if __name__ == "__main__":
    main()
