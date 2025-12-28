from scapy.all import sniff, Raw
import re
from datetime import datetime

# -------- SIGNATURES DPI NIVEAU 2 --------
SIGNATURES = {
    "powershell_command": {
        "regex": r"powershell|ForEach-Object|char\]\$_",
        "score": 4
    },
    "malicious_domain": {
        "regex": r"\.top|\.xyz|\.monster",
        "score": 3
    },
    "php_c2": {
        "regex": r"GET\s+/.+\.php",
        "score": 5
    },
    "suspicious_user_agent": {
        "regex": r"User-Agent:.*PowerShell",
        "score": 3
    },
    "base64_payload": {
        "regex": r"[A-Za-z0-9+/]{40,}={0,2}",
        "score": 2
    }
}

ALERT_THRESHOLD = 5  # score minimum pour alerte

LOGFILE = "dpi_alerts.log"


def log_alert(payload, score, signature_name):
    with open(LOGFILE, "a") as f:
        f.write("\n---- ALERT ----\n")
        f.write(f"Time: {datetime.now()}\n")
        f.write(f"Signature: {signature_name}\n")
        f.write(f"Score: {score}\n")
        f.write(f"Payload:\n{payload}\n")
        f.write("------------------\n")


def analyse(packet):
    if not packet.haslayer(Raw):
        return

    payload = packet[Raw].load.decode(errors="ignore")
    total_score = 0
    matched_signatures = []

    # Vérification des signatures
    for name, sig in SIGNATURES.items():
        if re.search(sig["regex"], payload, re.IGNORECASE):
            total_score += sig["score"]
            matched_signatures.append(name)

    # Si rien détecté
    if total_score == 0:
        print(f"[OK] Payload sain")
        return

    # Si score faible (juste informatif)
    if total_score < ALERT_THRESHOLD:
        print(f"\033[93m[WARNING] Payload suspect (score={total_score}) → {matched_signatures}\033[0m")
        return

    # ALERTE CRITIQUE
    print(f"\033[91m[!!! ALERTE CRITIQUE !!!] Score={total_score} → {matched_signatures}\033[0m")
    print(f"Payload:\n{payload}")

    # Log dans fichier
    log_alert(payload, total_score, ", ".join(matched_signatures))


# Lancement de la capture
sniff(iface="ens33", prn=analyse)
