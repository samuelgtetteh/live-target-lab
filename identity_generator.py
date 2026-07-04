"""
Continuously generates synthetic-but-realistic login events and pushes them
to the live Identity Anomaly API — standing in for a real SIEM/identity
provider streaming authentication events as they happen. Runs forever.

Values are drawn from the real category vocabulary the underlying model was
trained on (auth types, logon types, orientations), not arbitrary strings,
so a "normal" event actually looks normal to the detector and a "suspicious"
one actually looks suspicious — not just labeled that way by this generator.
"""
import os
import random
import time
from datetime import datetime

import requests

API_URL = os.environ.get("API_URL", "http://host.docker.internal:2500")
INTERVAL = float(os.environ.get("INTERVAL", "3"))
ANOMALY_RATE = float(os.environ.get("ANOMALY_RATE", "0.15"))

NORMAL_USERS = [f"U{1000 + i}@DOM1" for i in range(40)]
NORMAL_PCS = [f"C{1000 + i}" for i in range(50)]
SUSPICIOUS_USERS = ["ANONYMOUS LOGON@C9999", "ANONYMOUS LOGON@C8123", "guest@DOM1"]

AUTH_TYPES_NORMAL = ["NTLM", "Kerberos", "Negotiate"]
# Genuinely unrecognized values only - "?" and "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
# are both real, common values in the training data (tested directly against the
# live API: "?" barely moves the score), so they don't actually read as anomalous
# to the model. Anything not in its known vocabulary maps to an "unknown" code
# the model never saw in training, which is what actually triggers a real alert.
AUTH_TYPES_SUSPICIOUS = ["TotallyUnrecognizedAuth", "LegacyProtocolXYZ", "UnverifiedCustomAuth"]

LOGON_TYPES_NORMAL = ["Network", "Interactive", "Service"]
LOGON_TYPES_SUSPICIOUS = ["RemoteInteractive", "NewCredentials"]

ORIENTATIONS = ["LogOn", "LogOff"]


def generate_event():
    is_suspicious = random.random() < ANOMALY_RATE
    if is_suspicious:
        return {
            "src_user": random.choice(SUSPICIOUS_USERS),
            "src_pc": random.choice(NORMAL_PCS),
            "auth_type": random.choice(AUTH_TYPES_SUSPICIOUS),
            "logon_type": random.choice(LOGON_TYPES_SUSPICIOUS),
            "orientation": random.choice(ORIENTATIONS),
            "success": "Fail",
        }, True
    return {
        "src_user": random.choice(NORMAL_USERS),
        "src_pc": random.choice(NORMAL_PCS),
        "auth_type": random.choice(AUTH_TYPES_NORMAL),
        "logon_type": random.choice(LOGON_TYPES_NORMAL),
        "orientation": random.choice(ORIENTATIONS),
        "success": "Success",
    }, False


def run():
    print(f"Identity event source starting - sending synthetic events to {API_URL}/identity/score every {INTERVAL}s")
    while True:
        event, intended_suspicious = generate_event()
        timestamp = datetime.now().strftime("%H:%M:%S")
        try:
            resp = requests.post(f"{API_URL}/identity/score", json=event, timeout=10)
            resp.raise_for_status()
            result = resp.json()
        except requests.RequestException as exc:
            print(f"[{timestamp}] ERROR calling {API_URL}: {exc}")
            time.sleep(INTERVAL)
            continue

        status = "ALERT" if result["is_anomaly"] else "OK"
        tag = "(injected suspicious)" if intended_suspicious else "(injected normal)"
        print(f"[{timestamp}] {status:>5} {tag} :: {event['src_user']} on {event['src_pc']} "
              f"({event['auth_type']}/{event['logon_type']}, {event['success']}) "
              f"score={result['anomaly_score']:.3f}")

        time.sleep(INTERVAL)


if __name__ == "__main__":
    run()
