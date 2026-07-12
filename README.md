# Live Target Lab

Two standing Docker services that continuously generate synthetic-but-realistic events and push them to the live [Identity Anomaly](https://github.com/samuelgtetteh/ai-cybersecurity-portfolio) and OT/ICS Intrusion Detection APIs — a persistent "fake live source," analogous to what [cloud-target-lab](https://github.com/samuelgtetteh/cloud-target-lab) is for cloud/NIST control scanning, but for the two detection models instead.

Unlike a one-shot replay script, these run forever (`restart: unless-stopped`) and generate fresh synthetic data each tick rather than looping through a fixed historical dataset — closer to what a real SIEM or SCADA historian would look like continuously streaming live events.

## Services

- **`identity-event-source`** — generates synthetic login events (real category vocabulary: auth types, logon types, orientations) and POSTs them to `/identity/score`. ~15% are intentionally suspicious (anonymous logon, unusual auth type, failed remote interactive login).
- **`ics-event-source`** — generates synthetic sensor readings (small jitter around a real recorded baseline) and POSTs them to `/ics/score`. ~15% inject a large spike on 1-3 random sensors, simulating a cyber-physical attack or equipment fault.

Both log every event with a `[timestamp] OK/ALERT (injected normal/suspicious) ... verdict=<id>` line, so you can visually compare what was *intended* against what the live model actually *detected*.

## Ground-truth feedback (labels the live trail)

Because each source knows the label it *injected*, it reports that label back to the backend's decision layer, closing the loop. After scoring an event, the source reads the `X-Verdict-Id` header the API returns and POSTs the known label to `POST /decision/verdicts/{id}/feedback` (`malicious` for injected suspicious/attack, `benign` for normal). This is the same generic feedback channel a real analyst or SOAR tool would use in production — the event source simply plays that role here because it alone knows the truth.

The effect: the backend's persistent verdict trail is automatically labelled with ground truth, so it can compute **live precision/recall/specificity** from the database (`GET /decision/metrics`) — persisting what previously had to be tallied from these logs by hand. Feedback is best-effort: if the backend is an older build without the `/decision` endpoints, the missing header is simply ignored and streaming continues. Set `FEEDBACK=0` to disable.

## Usage

Requires the backend API (`ai-cybersecurity-portfolio/backend/`) already running and reachable at `http://host.docker.internal:2500` (adjust the `API_URL` environment variable in `docker-compose.yml` if it's running elsewhere).

```bash
docker compose up -d
docker compose logs -f
```

Stop with `docker compose down`.

## Configuration

Environment variables (set in `docker-compose.yml`):

| Variable | Default | Purpose |
|---|---|---|
| `API_URL` | `http://host.docker.internal:2500` | Base URL of the backend API |
| `INTERVAL` | `3` | Seconds between generated events |
| `ANOMALY_RATE` | `0.15` | Fraction of events intentionally generated as suspicious/attack |
| `FEEDBACK` | `1` | Report the injected label back to `/decision/.../feedback` (`0` to disable) |
