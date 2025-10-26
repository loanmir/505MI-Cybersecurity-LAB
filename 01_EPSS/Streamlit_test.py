import streamlit as st
import pandas as pd
import requests
import datetime
import os
import matplotlib.pyplot as plt

# --- STREAMLIT CONFIG ---
st.set_page_config(page_title="EPSS Tracker", layout="wide")
st.title("📊 EPSS Score Tracker")
st.write("Track the Exploit Prediction Scoring System (EPSS) scores of selected vulnerabilities over time.")

# --- USER INPUT ---
st.sidebar.header("Configuration")
vulns = st.sidebar.text_area(
    "Enter up to 10 CVE IDs (one per line):",
    "CVE-2025-9758\nCVE-2025-9789\nCVE-2025-9791\nCVE-2025-9794\nCVE-2025-9829\nCVE-2025-10097\nCVE-2025-10687\nCVE-2025-10768\nCVE-2025-10769\nCVE-2025-10779"
).splitlines()

vulns = [v.strip() for v in vulns if v.strip()]
data_file = "epss_history.csv"

# --- FETCH EPSS DATA FUNCTION ---
@st.cache_data(ttl=86400)  # cache for 1 day
def fetch_epss_scores(cves, date=None):
    """Fetch EPSS scores for given CVEs on a specific date (defaults to today)."""
    url = "https://api.first.org/data/v1/epss"
    params = {"cve": ",".join(cves)}
    if date:
        params["date"] = date  # format: YYYY-MM-DD
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", [])
        df = pd.DataFrame(data)
        df["epss"] = df["epss"].astype(float)
        df["percentile"] = df["percentile"].astype(float)
        # use the date from API response or the provided date parameter
        if "date" in df.columns:
            df["date"] = pd.to_datetime(df["date"])
        else:
            df["date"] = pd.to_datetime(date or "today")
        df["date"] = df["date"].dt.normalize()
        return df[["cve", "epss", "percentile", "date"]]
    except Exception as e:
        st.error(f"Error fetching EPSS data: {e}")
        return pd.DataFrame(columns=["cve", "epss", "percentile", "date"])

# --- LOAD EXISTING DATA ---
if os.path.exists(data_file):
    history_df = pd.read_csv(data_file, parse_dates=["date"])
    # ensure a consistent datetime64[ns] dtype for the date column
    history_df["date"] = pd.to_datetime(history_df["date"])
else:
    history_df = pd.DataFrame(columns=["cve", "epss", "percentile", "date"])

# --- PLOT RANGE: start from 2025-10-01 (inclusive) ---
START_DATE = pd.to_datetime("2025-10-01").normalize()

# --- FETCH NEW DATA ---
if st.sidebar.button("🔄 Fetch Latest EPSS Scores"):
    new_data = fetch_epss_scores(vulns)
    if not new_data.empty:
        # make sure new_data.date is datetime64[ns] before concat to avoid FutureWarning
        new_data["date"] = pd.to_datetime(new_data["date"])
        history_df = pd.concat([history_df, new_data], ignore_index=True)
        history_df.drop_duplicates(subset=["cve", "date"], keep="last", inplace=True)
        history_df.to_csv(data_file, index=False)
        st.success("✅ EPSS data updated successfully!")

# --- BACKFILL HISTORICAL DATA ---
if st.sidebar.button("📥 Backfill Historical Data (Oct 1 - Today)"):
    st.info("Fetching historical EPSS scores... This may take a moment.")
    date_range = pd.date_range(start=START_DATE, end=pd.to_datetime("today").normalize(), freq="D")
    all_historical = []
    
    progress_bar = st.sidebar.progress(0)
    for i, date in enumerate(date_range):
        date_str = date.strftime("%Y-%m-%d")
        daily_data = fetch_epss_scores(vulns, date=date_str)
        if not daily_data.empty:
            all_historical.append(daily_data)
        progress_bar.progress((i + 1) / len(date_range))
    
    if all_historical:
        historical_df = pd.concat(all_historical, ignore_index=True)
        historical_df["date"] = pd.to_datetime(historical_df["date"])
        history_df = pd.concat([history_df, historical_df], ignore_index=True)
        history_df.drop_duplicates(subset=["cve", "date"], keep="last", inplace=True)
        history_df.to_csv(data_file, index=False)
        st.success(f"✅ Backfilled {len(all_historical)} days of historical data!")
    else:
        st.warning("No historical data found.")

# --- FILTER DATA FOR SELECTED VULNS ---
filtered = history_df[history_df["cve"].isin(vulns) & (history_df["date"] >= START_DATE)]

if filtered.empty:
    st.warning("No EPSS data available yet. Click the button to fetch live scores.")
else:
    # --- PLOT LINE GRAPH ---
    st.subheader("📈 EPSS Score Trends Over Time")

    # pivot and reindex to a full daily range from START_DATE to today, forward-fill missing values
    pivot_df = filtered.pivot(index="date", columns="cve", values="epss").sort_index()
    # plot from START_DATE to the last fetched date (not today)
    last_fetch_date = pd.to_datetime(filtered["date"].max())
    full_index = pd.date_range(start=START_DATE, end=last_fetch_date, freq="D")
    pivot_df = pivot_df.reindex(full_index).ffill()

    fig, ax = plt.subplots(figsize=(10, 5))
    pivot_df.plot(ax=ax)
    ax.set_title("EPSS Score History")
    ax.set_xlabel("Date")
    ax.set_ylabel("EPSS Score")
    ax.legend(title="CVE ID", bbox_to_anchor=(1.05, 1), loc="upper left")
    st.pyplot(fig)

    # --- DISPLAY TABLE ---
    st.subheader("🧮 Latest EPSS Data")
    latest_date = pd.to_datetime(filtered["date"].max())
    latest = filtered[filtered["date"] == latest_date].sort_values("epss", ascending=False)
    st.dataframe(latest.reset_index(drop=True))

    st.caption(f"Last updated: {latest_date.date()} | Data source: FIRST.org EPSS API")
