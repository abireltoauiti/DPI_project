from scapy.all import sniff, Raw
import re
from datetime import datetime
import base64
import string

# -------- SIGNATURES DPI NIVEAU 2 --------
SIGNATURES = {
    "powershell_command": {"regex": r"powershell|ForEach-Object|char\]\$_", "score": 4},
    "malicious_domain": {"regex": r"\.top|\.xyz|\.monster", "score": 3},
    "php_c2": {"regex": r"GET\s+/.+\.php", "score": 5},
    "suspicious_user_agent": {"regex": r"User-Agent:.*PowerShell", "score": 3},
    "base64_payload": {"regex": r"[A-Za-z0-9+/]{40,}={0,2}", "score": 2}
}

ALERT_THRESHOLD = 5
LOGFILE = "dpi_alerts.log"


def is_printable(s):
    """Vérifie si la chaîne est majoritairement imprimable"""
    return all(c in string.printable or c in '\r\n\t' for c in s)


def format_payload(payload_bytes):
    """Retourne le payload en clair si imprimable, sinon en Base64"""
    try:
        decoded = payload_bytes.decode(errors="ignore")
        if is_printable(decoded):
            return decoded
        else:
            return base64.b64encode(payload_bytes).decode()
    except Exception:
        return base64.b64encode(payload_bytes).decode()


def log_alert(payload, score, signature_name):
    """Enregistre une alerte critique dans le fichier log"""
    with open(LOGFILE, "a") as f:
        f.write("\n---- ALERT ----\n")
        f.write(f"Time: {datetime.now()}\n")
        f.write(f"Signature: {signature_name}\n")
        f.write(f"Score: {score}\n")
        f.write(f"Payload:\n{payload}\n")
        f.write("------------------\n")


def analyse(packet):
    """Analyse un paquet et retourne un dictionnaire avec status et payload formaté"""
    if not packet.haslayer(Raw):
        return None

    payload_bytes = packet[Raw].load
    payload_formatted = format_payload(payload_bytes)
    total_score = 0
    matched_signatures = []

    # Vérification des signatures
    for name, sig in SIGNATURES.items():
        if re.search(sig["regex"], payload_formatted, re.IGNORECASE):
            total_score += sig["score"]
            matched_signatures.append(name)

    # Aucun problème détecté
    if total_score == 0:
        print(f"[OK] Payload sain")
        return {"status": "ok", "payload": payload_formatted}

    # Warning (score faible)
    if total_score < ALERT_THRESHOLD:
        print(f"\033[93m[WARNING] Payload suspect (score={total_score}) → {matched_signatures}\033[0m")
        return {"status": "warning", "score": total_score, "signatures": matched_signatures, "payload": payload_formatted}

    # Alerte critique
    print(f"\033[91m[!!! ALERTE CRITIQUE !!!] Score={total_score} → {matched_signatures}\033[0m")
    print(f"Payload:\n{payload_formatted}")
    log_alert(payload_formatted, total_score, ", ".join(matched_signatures))

    return {"status": "critical", "score": total_score, "signatures": matched_signatures, "payload": payload_formatted}


def start_dpi(iface="ens33", packet_count=0, callback=None):
    """Lance la capture DPI et utilise callback pour chaque paquet analysé"""
    def handle(pkt):
        result = analyse(pkt)
        if callback:
            callback(result)

    print("🔵 DPI démarré…")
    sniff(iface=iface, prn=handle, count=packet_count)

