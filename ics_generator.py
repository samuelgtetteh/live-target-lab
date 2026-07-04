"""
Continuously generates synthetic-but-realistic sensor telemetry and pushes
it to the live OT/ICS Intrusion Detection API — standing in for a real SCADA
historian streaming sensor readings as they happen. Runs forever.

"Normal" ticks perturb a real recorded baseline reading with small random
jitter (mimicking natural sensor noise); "attack" ticks additionally spike a
handful of randomly chosen sensors to an extreme value, the way a real
cyber-physical attack (or equipment fault) would show up as a sudden,
implausible reading rather than gradual drift.
"""
import os
import random
import time
from datetime import datetime

import requests

API_URL = os.environ.get("API_URL", "http://host.docker.internal:2500")
INTERVAL = float(os.environ.get("INTERVAL", "3"))
ANOMALY_RATE = float(os.environ.get("ANOMALY_RATE", "0.15"))
NORMAL_NOISE_STDS = 0.05  # normal jitter: a fraction of the sensor's real trained std dev
ATTACK_SPIKE_STDS = 25    # attack spike: many std devs away - implausible for real sensor drift

# A real recorded normal reading (same baseline used by ics_api.py's fallback)
BASELINE_READING = {
    "P1_B2004": 0.0983, "P1_B2016": 0.9481, "P1_B3004": 399.2321, "P1_B3005": 1110.3986,
    "P1_B4002": 32.0, "P1_B4005": 0.0, "P1_B400B": 32.9705, "P1_B4022": 35.3325,
    "P1_FCV01D": 0.0, "P1_FCV01Z": 0.2838, "P1_FCV02D": 100.0, "P1_FCV02Z": 95.5368,
    "P1_FCV03D": 53.7863, "P1_FCV03Z": 54.3228, "P1_FT01": 115.6234, "P1_FT01Z": 579.1716,
    "P1_FT02": 6.1417, "P1_FT02Z": 31.9776, "P1_FT03": 310.936, "P1_FT03Z": 1111.5228,
    "P1_LCV01D": 21.9717, "P1_LCV01Z": 21.7834, "P1_LIT01": 395.0419, "P1_PCV01D": 30.7836,
    "P1_PCV01Z": 31.4728, "P1_PCV02D": 12.0, "P1_PCV02Z": 12.0102, "P1_PIT01": 0.8943,
    "P1_PIT02": 0.2153, "P1_TIT01": 35.8032, "P1_TIT02": 37.146, "P2_24Vdc": 28.0246,
    "P2_Auto": 1.0, "P2_Emgy": 0.0, "P2_On": 1.0, "P2_SD01": 20.0, "P2_SIT01": 814.0,
    "P2_TripEx": 0.0, "P2_VT01e": 11.8639, "P2_VXT02": -3.2829, "P2_VXT03": -1.2577,
    "P2_VYT02": 0.4135, "P2_VYT03": 1.8313, "P3_LCP01D": 4.0, "P3_LCV01D": 0.0,
    "P3_LH": 70.0, "P3_LL": 10.0, "P3_LT01": 68.95255, "P4_HT_FD": -0.0001,
    "P4_HT_LD": -0.0072, "P4_HT_PO": 0.0724, "P4_HT_PS": 0.0, "P4_LD": 300.9802,
    "P4_ST_FD": -0.003, "P4_ST_LD": 298.0324, "P4_ST_PO": 287.1274, "P4_ST_PS": 50.9871,
    "P4_ST_PT01": 9916.0, "P4_ST_TT01": 27627.0,
}

# Real per-sensor standard deviation from the trained scaler (scaler_hai.pkl) -
# NOT a percentage of the raw value. An earlier version used "2% of the raw
# value" as noise, which was wrong: some sensors (e.g. P4_ST_TT01, baseline
# ~27,627) have a real trained std dev of only ~31, so 2%-of-value noise
# (~552) was ~17x larger than anything the model ever saw as normal, causing
# even "normal" synthetic ticks to score as a false alarm. Noise here must be
# scaled to each sensor's own real variability, not its raw magnitude.
SENSOR_STD = {
    "P1_B2004": 0.032222, "P1_B2016": 0.180443, "P1_B3004": 20.935342, "P1_B3005": 44.396139,
    "P1_B4002": 0.30067, "P1_B4005": 39.797257, "P1_B400B": 1207.850962, "P1_B4022": 0.502577,
    "P1_FCV01D": 35.382451, "P1_FCV01Z": 38.703419, "P1_FCV02D": 49.207232, "P1_FCV02Z": 44.592598,
    "P1_FCV03D": 3.424601, "P1_FCV03Z": 3.444529, "P1_FT01": 36.907085, "P1_FT01Z": 121.411233,
    "P1_FT02": 870.841435, "P1_FT02Z": 1207.849807, "P1_FT03": 27.289895, "P1_FT03Z": 48.319611,
    "P1_LCV01D": 4.26863, "P1_LCV01Z": 4.273116, "P1_LIT01": 24.630962, "P1_PCV01D": 27.485767,
    "P1_PCV01Z": 27.810116, "P1_PCV02D": 0.115073, "P1_PCV02Z": 0.257412, "P1_PIT01": 0.150819,
    "P1_PIT02": 0.575212, "P1_TIT01": 0.587547, "P1_TIT02": 1.27662, "P2_24Vdc": 0.003118,
    "P2_Auto": 1.0, "P2_Emgy": 1.0, "P2_On": 1.0, "P2_SD01": 9.258307, "P2_SIT01": 34.623798,
    "P2_TripEx": 1.0, "P2_VT01e": 0.076491, "P2_VXT02": 0.483423, "P2_VXT03": 0.329429,
    "P2_VYT02": 0.488763, "P2_VYT03": 0.383625, "P3_LCP01D": 5343.013677, "P3_LCV01D": 6840.76706,
    "P3_LH": 1.0, "P3_LL": 1.0, "P3_LT01": 18.15908, "P4_HT_FD": 0.002077, "P4_HT_LD": 33.458475,
    "P4_HT_PO": 31.405069, "P4_HT_PS": 1.0, "P4_LD": 60.345989, "P4_ST_FD": 0.001869,
    "P4_ST_LD": 34.19241, "P4_ST_PO": 30.625264, "P4_ST_PS": 20.310182, "P4_ST_PT01": 44.548164,
    "P4_ST_TT01": 31.393294,
}
SENSOR_NAMES = list(BASELINE_READING.keys())


def generate_reading():
    readings = {
        k: v + random.gauss(0, SENSOR_STD[k] * NORMAL_NOISE_STDS)
        for k, v in BASELINE_READING.items()
    }

    is_attack = random.random() < ANOMALY_RATE
    if is_attack:
        for sensor in random.sample(SENSOR_NAMES, k=random.randint(1, 3)):
            direction = random.choice([-1, 1])
            readings[sensor] = BASELINE_READING[sensor] + direction * ATTACK_SPIKE_STDS * SENSOR_STD[sensor]

    return readings, is_attack


def run():
    print(f"ICS event source starting - sending synthetic sensor readings to {API_URL}/ics/score every {INTERVAL}s")
    while True:
        readings, intended_attack = generate_reading()
        timestamp = datetime.now().strftime("%H:%M:%S")
        try:
            resp = requests.post(f"{API_URL}/ics/score", json={"readings": readings}, timeout=10)
            resp.raise_for_status()
            result = resp.json()
        except requests.RequestException as exc:
            print(f"[{timestamp}] ERROR calling {API_URL}: {exc}")
            time.sleep(INTERVAL)
            continue

        status = "ALERT" if result["is_anomaly"] else "OK"
        tag = "(injected attack)" if intended_attack else "(injected normal)"
        print(f"[{timestamp}] {status:>5} {tag} :: reconstruction_error={result['reconstruction_error']:.4f} "
              f"(threshold={result['threshold']})")

        time.sleep(INTERVAL)


if __name__ == "__main__":
    run()
