# Large Outbound Transfer Anomaly --

1. Sample Logs

## Baseline
- User usually uploads ~50MB to GitHub daily

{
  "timestamp": "2026-03-20T10:00:00Z",
  "user": "Dev-Alice",
  "bytes_sent": 52428800,
  "destination": "github.com",
  "avg_daily_volume": "48MB"
}

## The Anomaly (Spike)
- User's account suddenly uploads 15GB to an unknown IP address at 3:00 am

{
  "timestamp": "2026-03-30T03:15:22Z",
  "user": "Dev-Alice",
  "bytes_sent": 16106127360,
  "destination": "93.184.216.34",
  "anomaly_score": 98.2
}

Logic: Uses ML or User and Entity Behavior Analytics (UEBA)

Calculate a moving average of "Bytes Sent" per user over 30 days. Trigger an alert if a single session exceeds the 95th percentile of their historical volume

The "Math" (Z-score): Z = (x−μ) / σ​

x - current activity
μ - the mean
σ​ - stadard deviation

Query (SQL/KQL)

-- Step 1: Calculate the historical baseline per user
WITH Baseline AS (
    SELECT user, AVG(bytes_sent) as avg_hourly_sent
    FROM network_logs
    WHERE timestamp > now() - interval '30 days'
    GROUP BY user
),
-- Step 2: Capture current activity
CurrentActivity AS (
    SELECT user, SUM(bytes_sent) as current_sent
    FROM network_logs
    WHERE timestamp > now() - interval '1 hour'
    GROUP BY user
)
-- Step 3: Flag the outliers
SELECT C.user, C.current_sent, B.avg_hourly_sent
FROM CurrentActivity C
JOIN Baseline B ON C.user = B.user
WHERE C.current_sent > (B.avg_hourly_sent * 5) 
  AND C.current_sent > 104857600 -- Filter to ignore small spikes (e.g., > 100MB)