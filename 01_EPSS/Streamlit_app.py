import streamlit as st
import pandas as pd
import requests
import datetime
import os
import time

# --- STREAMLIT CONFIG ---
st.set_page_config(page_title="EPSS Tracker", layout="wide")
st.title("EPSS Score Tracker")
st.write("Track the Exploit Prediction Scoring System (EPSS) scores of selected vulnerabilities over time.")

# --- USER INPUT ---
st.sidebar.header("Configuration")
vulns = st.sidebar.text_area(
    "Enter up to 10 CVE IDs (one per line):",
    "CVE-2025-9789\nCVE-2025-10769\nCVE-2025-9796\nCVE-2025-9801\nCVE-2025-9800\nCVE-2025-10083\nCVE-2025-10779\nCVE-2025-11031\nCVE-2025-9794\nCVE-2025-9923"
).splitlines()

vulns = [v.strip() for v in vulns if v.strip()]
data_file = "epss_history.csv"

# --- FETCH EPSS DATA FUNCTION ---
@st.cache_data(ttl=86400)
def fetch_epss_scores(cves, date=None):
    url = "https://api.first.org/data/v1/epss"
    params = {"cve": ",".join(cves)}
    if date:
        params["date"] = date
        
    # Retry up to 3 times if the server fails
    for attempt in range(3):
        try:
            response = requests.get(url, params=params, timeout=10)
            
            # If we get a 404 or 422, it usually means data isn't ready for that specific day.
            if response.status_code in [404, 422]:
                return pd.DataFrame(columns=["cve", "epss", "percentile", "date"])
                
            response.raise_for_status() # Raises error for 500/502/503
            
            data = response.json().get("data", [])
            if not data: 
                return pd.DataFrame(columns=["cve", "epss", "percentile", "date"])
                
            df = pd.DataFrame(data)
            df["epss"] = df["epss"].astype(float)
            df["percentile"] = df["percentile"].astype(float)
            
            if "date" in df.columns:
                df["date"] = pd.to_datetime(df["date"])
            else:
                df["date"] = pd.to_datetime(date or "today")
            
            df["date"] = df["date"].dt.normalize()
            return df[["cve", "epss", "percentile", "date"]]

        except requests.exceptions.RequestException:
            # If server error (502), wait 2 seconds and try again
            time.sleep(2)
    
    return pd.DataFrame(columns=["cve", "epss", "percentile", "date"])


if os.path.exists(data_file):
    try:
        history_df = pd.read_csv(data_file)
        history_df["date"] = pd.to_datetime(history_df["date"])
    except Exception:
        # If file is corrupt, start fresh
        history_df = pd.DataFrame(columns=["cve", "epss", "percentile", "date"])
else:
    history_df = pd.DataFrame(columns=["cve", "epss", "percentile", "date"])
# -----------------------------------------------------------

# --- PLOT RANGE: start from 2025-10-01 (inclusive) ---
START_DATE = pd.to_datetime("2025-10-01").normalize()

# --- FETCH NEW DATA ---
if st.sidebar.button("Fetch Latest EPSS Scores"):
    new_data = fetch_epss_scores(vulns)
    if not new_data.empty:
        new_data["date"] = pd.to_datetime(new_data["date"])
        history_df = pd.concat([history_df, new_data], ignore_index=True)
        history_df.drop_duplicates(subset=["cve", "date"], keep="last", inplace=True)
        history_df.to_csv(data_file, index=False)
        st.success("EPSS data updated successfully!")
        st.rerun()

# --- BACKFILL HISTORICAL DATA ---
if st.sidebar.button("Backfill Historical Data"):
    st.info("Fetching historical data... (Slow mode enabled to prevent errors)")
    
    # Stop at yesterday to avoid 422 errors for "future" data
    yesterday = pd.to_datetime("today").normalize() - pd.Timedelta(days=1)
    
    # Ensure we don't try to backfill if START_DATE is in the future relative to yesterday
    if START_DATE > yesterday:
         st.warning("Start date is in the future. Nothing to backfill.")
    else:
        date_range = pd.date_range(start=START_DATE, end=yesterday, freq="D")
        
        all_historical = []
        progress_bar = st.sidebar.progress(0)
        status_text = st.sidebar.empty()
        
        for i, date in enumerate(date_range):
            date_str = date.strftime("%Y-%m-%d")
            
            # Check if we already have this date in our CSV to skip API call
            if not history_df.empty and (history_df['date'] == date).any():
                status_text.text(f"Skipping {date_str} (already exists)")
            else:
                status_text.text(f"Fetching {date_str}...")
                daily_data = fetch_epss_scores(vulns, date=date_str)
                if not daily_data.empty:
                    all_historical.append(daily_data)
                
                # CRITICAL: Sleep 0.2 seconds between requests to avoid 502/Timeout
                time.sleep(0.2) 
                
            progress_bar.progress((i + 1) / len(date_range))
        
        status_text.empty()
        
        if all_historical:
            historical_df = pd.concat(all_historical, ignore_index=True)
            historical_df["date"] = pd.to_datetime(historical_df["date"])
            
            history_df = pd.concat([history_df, historical_df], ignore_index=True)
            history_df.drop_duplicates(subset=["cve", "date"], keep="last", inplace=True)
            history_df.to_csv(data_file, index=False)
            st.success(f"Success! Added {len(all_historical)} days of data.")
            st.rerun()
        else:
            st.warning("No new historical data found (or all dates were already cached).")

# --- FILTER DATA FOR SELECTED VULNS ---
filtered = history_df[history_df["cve"].isin(vulns) & (history_df["date"] >= START_DATE)]

if filtered.empty:
    st.warning("No EPSS data available yet. Click the button to fetch live scores.")
else:
    # --- PLOT LINE GRAPH ---
    st.subheader("EPSS Score Trends")

    # Pivot the data so dates are rows and CVEs are columns
    chart_data = filtered.pivot(index="date", columns="cve", values="epss")

    # Native Streamlit Line Chart
    st.line_chart(chart_data)

    # --- DISPLAY TABLE ---
    st.subheader("Latest EPSS Data")
    latest_date = pd.to_datetime(filtered["date"].max())
    latest = filtered[filtered["date"] == latest_date].sort_values("epss", ascending=False)
    
    # Nice formatting for the table
    st.dataframe(
        latest.style.format({"epss": "{:.4f}", "percentile": "{:.2f}"}),
        use_container_width=True
    )

    st.caption(f"Last updated: {latest_date.date()} | Data source: FIRST.org EPSS API")