"""
anomaly_detection.py — Unsupervised anomaly detection over log-derived features.

Rather than running ML directly on raw text, we engineer per-source-IP
behavioral features over rolling time windows (a standard approach in
security analytics), then use an Isolation Forest to flag outliers:
statistically unusual combinations of failed logins, distinct users
attempted, request rate, and error rate.

Flagged anomalies are written back as `ml_anomaly` alerts.
"""
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest

from models import get_conn, insert_alert

WINDOW_MINUTES = 10


def load_logs_df():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT timestamp, source, severity, event_type, ip_address, user FROM logs "
            "WHERE ip_address IS NOT NULL"
        ).fetchall()
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame([dict(r) for r in rows])
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df.dropna(subset=["timestamp"])
    return df


def build_features(df):
    """Aggregate per (ip, time window) behavioral features."""
    if df.empty:
        return pd.DataFrame()

    df = df.copy()
    df["is_failed_login"] = (df["event_type"] == "login_failed").astype(int)
    df["is_success_login"] = (df["event_type"] == "login_success").astype(int)
    df["is_error_sev"] = df["severity"].isin(["WARNING", "ERROR", "CRITICAL"]).astype(int)

    window = pd.Grouper(key="timestamp", freq=f"{WINDOW_MINUTES}min")
    grouped = df.groupby(["ip_address", window])

    features = grouped.agg(
        total_events=("event_type", "count"),
        failed_logins=("is_failed_login", "sum"),
        successful_logins=("is_success_login", "sum"),
        distinct_users=("user", "nunique"),
        http_errors=("is_error_sev", "sum"),
    ).reset_index()

    features = features[features["total_events"] > 0]
    features = features.rename(columns={"timestamp": "window_start"})
    return features


def score_anomalies(features):
    if features.empty or len(features) < 5:
        return features.assign(anomaly_score=0.0, is_anomaly=False)

    feature_cols = ["total_events", "failed_logins", "successful_logins", "distinct_users", "http_errors"]
    X = features[feature_cols].fillna(0)

    # contamination='auto' lets the model decide the outlier fraction rather than
    # hardcoding an assumption about attack prevalence
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    model.fit(X)

    features = features.copy()
    features["anomaly_score"] = -model.decision_function(X)  # higher = more anomalous
    features["is_anomaly"] = model.predict(X) == -1
    return features


def persist_anomalies(features):
    anomalies = features[features["is_anomaly"]].sort_values("anomaly_score", ascending=False)
    now = datetime.now().isoformat()
    count = 0
    with get_conn() as conn:
        for _, row in anomalies.iterrows():
            if row["failed_logins"] < 2 and row["http_errors"] < 3:
                continue  # skip low-signal statistical noise
            desc = (
                f"Unusual activity from {row['ip_address']}: {int(row['failed_logins'])} failed logins, "
                f"{int(row['distinct_users'])} distinct users, {int(row['http_errors'])} error-level events "
                f"in a {WINDOW_MINUTES}-minute window (anomaly score {row['anomaly_score']:.2f})."
            )
            insert_alert(
                conn, now, "HIGH" if row["anomaly_score"] > 0.6 else "MEDIUM",
                "ml_anomaly", row["ip_address"], desc,
            )
            count += 1
    return count


def run():
    df = load_logs_df()
    features = build_features(df)
    scored = score_anomalies(features)
    n = persist_anomalies(scored)
    print(f"Anomaly detection complete. {n} ML-flagged alerts written "
          f"(from {len(scored)} IP/time-window feature rows).")
    return n


if __name__ == "__main__":
    run()
