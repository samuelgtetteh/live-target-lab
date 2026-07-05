"""
Continuously generates synthetic-but-realistic login events and pushes them
to the live Identity Anomaly API — standing in for a real SIEM/identity
provider streaming authentication events as they happen. Runs forever.

Normal traffic is single logins from ordinary users on ordinary machines.

An "attack" is modelled the way the detector actually recognises one: not a
single cosmetically-odd event, but a BEHAVIOURAL burst — one account rapidly
authenticating across many different machines in a short window (classic
credential-stuffing / lateral movement). This is what drives the model's
behavioural features (hourly_count, unique_pcs) upward, which is precisely the
signal that made ANONYMOUS LOGON the top anomaly in the original training data.
A lone event that only tweaks categorical fields (auth type, logon type) sits
near the decision boundary and is NOT reliably anomalous — the volume/breadth
of access is what matters, so that is what we simulate.
"""
import os
import random
import time
from datetime import datetime

import requests

API_URL = os.environ.get("API_URL", "http://host.docker.internal:2500")
INTERVAL = float(os.environ.get("INTERVAL", "3"))
ANOMALY_RATE = float(os.environ.get("ANOMALY_RATE", "0.15"))

# An attack tick emits a burst of this many logins from ONE account across this
# many distinct machines, fast enough to fall inside the model's rolling window.
ATTACK_BURST_MIN = int(os.environ.get("ATTACK_BURST_MIN", "8"))
ATTACK_BURST_MAX = int(os.environ.get("ATTACK_BURST_MAX", "12"))
BURST_GAP = float(os.environ.get("BURST_GAP", "0.3"))  # seconds between burst events

NORMAL_USERS = [f"U{1000 + i}@DOM1" for i in range(40)]
NORMAL_PCS = [f"C{1000 + i}" for i in range(50)]
SUSPICIOUS_USERS = ["ANONYMOUS LOGON@C9999", "ANONYMOUS LOGON@C8123", "guest@DOM1"]

AUTH_TYPES_NORMAL = ["NTLM", "Kerberos", "Negotiate"]
# Genuinely unrecognized values only - a secondary signal on top of the
# behavioural burst; anything not in the model's known vocabulary maps to an
# "unknown" code it never saw in training.
AUTH_TYPES_SUSPICIOUS = ["TotallyUnrecognizedAuth", "LegacyProtocolXYZ", "UnverifiedCustomAuth"]

LOGON_TYPES_NORMAL = ["Network", "Interactive", "Service"]
LOGON_TYPES_SUSPICIOUS = ["RemoteInteractive", "NewCredentials"]

ORIENTATIONS = ["LogOn", "LogOff"]


def make_normal_event():
    return {
        "src_user": random.choice(NORMAL_USERS),
        "src_pc": random.choice(NORMAL_PCS),
        "auth_type": random.choice(AUTH_TYPES_NORMAL),
        "logon_type": random.choice(LOGON_TYPES_NORMAL),
        "orientation": random.choice(ORIENTATIONS),
        "success": "Success",
    }


def make_attack_event(user, pc):
    return {
        "src_user": user,
        "src_pc": pc,
        "auth_type": random.choice(AUTH_TYPES_SUSPICIOUS),
        "logon_type": random.choice(LOGON_TYPES_SUSPICIOUS),
        "orientation": random.choice(ORIENTATIONS),
        "success": "Fail",
    }


def send_and_log(event, intended_suspicious):
    timestamp = datetime.now().strftime("%H:%M:%S")
    try:
        resp = requests.post(f"{API_URL}/identity/score", json=event, timeout=10)
        resp.raise_for_status()
        result = resp.json()
    except requests.RequestException as exc:
        print(f"[{timestamp}] ERROR calling {API_URL}: {exc}")
        return
    status = "ALERT" if result["is_anomaly"] else "OK"
    tag = "(injected suspicious)" if intended_suspicious else "(injected normal)"
    print(f"[{timestamp}] {status:>5} {tag} :: {event['src_user']} on {event['src_pc']} "
          f"({event['auth_type']}/{event['logon_type']}, {event['success']}) "
          f"score={result['anomaly_score']:.3f}")


def run():
    print(f"Identity event source starting - sending synthetic events to {API_URL}/identity/score every {INTERVAL}s")
    while True:
        if random.random() < ANOMALY_RATE:
            # Behavioural attack: one account authenticating across many hosts fast.
            user = random.choice(SUSPICIOUS_USERS)
            k = random.randint(ATTACK_BURST_MIN, ATTACK_BURST_MAX)
            pcs = random.sample(NORMAL_PCS, k=k)
            for pc in pcs:
                send_and_log(make_attack_event(user, pc), intended_suspicious=True)
                time.sleep(BURST_GAP)
        else:
            send_and_log(make_normal_event(), intended_suspicious=False)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    run()
