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
                            score_color = "red" if inc.severity_score > 80 else "orange" if inc.severity_score > 50 else "blue"
                            with st.expander(f"Incident {inc.id} | IP: {inc.primary_ip} | Severity: {inc.status} (Score: {inc.severity_score})"):
                                st.write(f"**Status:** {inc.status}")
                                st.write(f"**Risk Score:** :{score_color}[{inc.severity_score}/100]")
                                st.write(f"**Associated Alerts:** {len(inc.alerts)}")
                                
                                # Show alerts for this incident
                                inc_records = []
                                for a in inc.alerts:
                                    rec = vars(a).copy()
                                    # Simple mapping again (or could make helper global)
                                    if "AI Detection" in a.alert_type: rec['source'] = "🤖 AI"
                                    elif "Exfiltration" in a.alert_type: rec['source'] = "📤 Exfil"
                                    elif "Port Scan" in a.alert_type or "Suspicious" in a.alert_type: rec['source'] = "🕸️ Net"
                                    elif "Brute Force" in a.alert_type: rec['source'] = "🔐 Auth"
                                    else: rec['source'] = "🛡️ Gen"
                                    
                                    # Ensure mitre_id exists (for legacy alerts)
                                    if 'mitre_id' not in rec: rec['mitre_id'] = "N/A"
                                    
                                    inc_records.append(rec)
                                    
                                inc_df = pd.DataFrame(inc_records)
                                st.dataframe(
                                    inc_df, 
                                    column_order=["timestamp", "source", "mitre_id", "alert_type", "description"],
                                    use_container_width=True
                                )
                    else:
                        st.success("No active incidents detected.")

                with tab2:
                    st.subheader("Detailed Alert Log")
                    if all_alerts:
                        # Helper to categorize alerts
                        def get_source(alert_type):
                            if "AI Detection" in alert_type: return "🤖 AI Model"
                            if "Exfiltration" in alert_type: return "📤 Exfil Detection"
                            if "Port Scan" in alert_type or "Suspicious" in alert_type: return "🕸️ Network Rules"
                            if "Brute Force" in alert_type: return "🔐 Auth Rules"
                            return "🛡️ General"

                        # Convert to records and add Source
                        alert_records = []
                        for a in all_alerts:
                            rec = vars(a).copy()
                            rec['source_module'] = get_source(a.alert_type)
                            alert_records.append(rec)
                            
                        alerts_df = pd.DataFrame(alert_records)
                        
                        # Interactive filters
                        alert_types = st.multiselect("Filter by Type", alerts_df['alert_type'].unique())
                        if alert_types:
                            alerts_df = alerts_df[alerts_df['alert_type'].isin(alert_types)]
                            
                        st.dataframe(
                            alerts_df,
                            column_config={
                                "timestamp": st.column_config.DatetimeColumn("Time", format="D MMM HH:mm:ss"),
                                "severity": st.column_config.TextColumn("Severity"),
                                "source_module": st.column_config.TextColumn("Detection Module"),
                                "alert_type": st.column_config.TextColumn("Alert Type"),
                                "mitre_id": st.column_config.TextColumn("MITRE ID"),
                                "description": st.column_config.TextColumn("Description"),
                            },
                            column_order=["timestamp", "source_module", "severity", "mitre_id", "alert_type", "src_ip", "description"],
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
