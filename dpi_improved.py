from scapy.all import sniff, Raw, IP, TCP, UDP, DNS, ICMP, rdpcap
import re
from datetime import datetime
import base64
import string
import pandas as pd
import json
import threading
from queue import Queue
from collections import defaultdict
import signal
import sys

# ========== IMPROVEMENT 1: ENHANCED SIGNATURES ==========
SIGNATURES = {
    "powershell_command": {
        "regex": r"powershell|ForEach-Object|char\]\$_|Invoke-Expression|IEX",
        "score": 4,
        "category": "command_execution"
    },
    "malicious_domain": {
        "regex": r"\.top|\.xyz|\.monster|\.tk|\.ml",
        "score": 3,
        "category": "malicious_infrastructure"
    },
    "php_c2": {
        "regex": r"GET\s+/.+\.php\?cmd=|POST\s+/.+\.php",
        "score": 5,
        "category": "c2_communication"
    },
    "suspicious_user_agent": {
        "regex": r"User-Agent:.*(PowerShell|curl|wget|python-requests)",
        "score": 3,
        "category": "suspicious_tool"
    },
    "base64_payload": {
        "regex": r"[A-Za-z0-9+/]{100,}={0,2}",
        "score": 1,
        "category": "encoded_content"
    },
    "large_dns_query": {
        "regex": r"[a-z0-9]{50,}\.",
        "score": 6,
        "category": "data_exfiltration"
    },
    "file_upload_pattern": {
        "regex": r"Content-Disposition:.*filename=.*\.(zip|rar|7z|sql|db|tar|gz|bak)",
        "score": 5,
        "category": "data_exfiltration"
    },
    "sql_injection": {
        "regex": r"(union\s+select|or\s+1=1|;\s*drop\s+table|exec\s*\(|<script>)",
        "score": 7,
        "category": "injection_attack"
    },
    "password_in_url": {
        "regex": r"(password|passwd|pwd)=[\w\d]{3,}",
        "score": 4,
        "category": "credential_leak"
    },
    "api_key_leak": {
        "regex": r"(api[_-]?key|token|secret)[\"']?\s*[:=]\s*[\"']?[\w\d]{20,}",
        "score": 6,
        "category": "credential_leak"
    }
}

ALERT_THRESHOLD = 5
LOGFILE = "dpi_alerts.log"
REPORT_FILE = "dpi_report.json"

# ========== IMPROVEMENT 2: PACKET DATA STORAGE ==========
packet_data = []
packet_stats = {
    'syn_count': defaultdict(int),
    'dns_queries': defaultdict(int),
    'upload_sizes': defaultdict(int)
}

# ========== FIX 1: INCREASE QUEUE SIZE ==========
packet_queue = Queue(maxsize=5000)  # Increased from 1000 to 5000
is_running = False
sniff_thread = None

def is_printable(s):
    """Check if string is mostly printable"""
    return all(c in string.printable or c in '\r\n\t' for c in s)

def format_payload(payload_bytes):
    """Return payload as plaintext if printable, otherwise base64"""
    try:
        decoded = payload_bytes.decode(errors="ignore")
        if is_printable(decoded):
            return decoded
        else:
            return f"[BASE64] {base64.b64encode(payload_bytes[:100]).decode()}..."
    except Exception:
        return f"[BASE64] {base64.b64encode(payload_bytes[:100]).decode()}..."

# ========== IMPROVEMENT 4: PROTOCOL-LEVEL ANALYSIS ==========
def analyse_protocol_behavior(packet):
    """Detect protocol-level anomalies and exfiltration attempts"""
    anomalies = []
    score_bonus = 0
    
    # TCP Analysis
    if packet.haslayer(TCP):
        if packet[TCP].flags == 'S':
            src_ip = packet[IP].src if packet.haslayer(IP) else 'unknown'
            packet_stats['syn_count'][src_ip] += 1
            if packet_stats['syn_count'][src_ip] > 50:
                anomalies.append("potential_syn_flood")
                score_bonus += 4
        
        sensitive_ports = [22, 23, 3389, 445, 1433, 3306]
        if packet[TCP].dport in sensitive_ports:
            anomalies.append(f"sensitive_port_access:{packet[TCP].dport}")
            score_bonus += 2
    
    # FIX 2: DNS Analysis only on port 53
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        if packet.haslayer(UDP) and packet[UDP].dport == 53:
            try:
                query = packet[DNS].qd.qname.decode()
                if len(query) > 50:
                    anomalies.append("dns_tunneling_suspicious_length")
                    score_bonus += 6
                
                src_ip = packet[IP].src if packet.haslayer(IP) else 'unknown'
                packet_stats['dns_queries'][src_ip] += 1
                if packet_stats['dns_queries'][src_ip] > 100:
                    anomalies.append("excessive_dns_queries")
                    score_bonus += 3
            except:
                pass
    
    # ICMP Tunneling
    if packet.haslayer(ICMP) and packet.haslayer(Raw):
        payload_size = len(packet[Raw].load)
        if payload_size > 56:
            anomalies.append(f"icmp_data_exfiltration:{payload_size}_bytes")
            score_bonus += 5
    
    # Large upload detection
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport in [80, 443, 8080]:
            payload_size = len(packet[Raw].load)
            if payload_size > 10000:
                src_ip = packet[IP].src if packet.haslayer(IP) else 'unknown'
                packet_stats['upload_sizes'][src_ip] += payload_size
                anomalies.append(f"large_upload:{payload_size}_bytes")
                score_bonus += 4
    
    return anomalies, score_bonus

def log_alert(payload, score, signature_name, packet_info, anomalies):
    """Log critical alerts with full context"""
    with open(LOGFILE, "a") as f:
        f.write("\n" + "="*50 + "\n")
        f.write("🚨 CRITICAL ALERT\n")
        f.write("="*50 + "\n")
        f.write(f"Time: {datetime.now()}\n")
        f.write(f"Signature(s): {signature_name}\n")
        f.write(f"Threat Score: {score}\n")
        f.write(f"\nPacket Info:\n")
        f.write(f"  Source: {packet_info.get('src_ip', 'N/A')}:{packet_info.get('src_port', 'N/A')}\n")
        f.write(f"  Destination: {packet_info.get('dst_ip', 'N/A')}:{packet_info.get('dst_port', 'N/A')}\n")
        f.write(f"  Protocol: {packet_info.get('protocol', 'N/A')}\n")
        f.write(f"  Payload Size: {packet_info.get('payload_size', 0)} bytes\n")
        if anomalies:
            f.write(f"\nProtocol Anomalies: {', '.join(anomalies)}\n")
        f.write(f"\nPayload Preview:\n{payload[:500]}\n")
        f.write("="*50 + "\n\n")

def analyse(packet):
    """Main analysis function with comprehensive inspection"""
    if not packet.haslayer(Raw):
        return None
    
    payload_bytes = packet[Raw].load
    payload_formatted = format_payload(payload_bytes)
    
    # ========== EXTRACT PACKET METADATA ==========
    packet_info = {
        'timestamp': datetime.now(),
        'src_ip': packet[IP].src if packet.haslayer(IP) else 'N/A',
        'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'N/A',
        'src_port': packet.sport if (packet.haslayer(TCP) or packet.haslayer(UDP)) else 'N/A',
        'dst_port': packet.dport if (packet.haslayer(TCP) or packet.haslayer(UDP)) else 'N/A',
        'protocol': 'TCP' if packet.haslayer(TCP) else 'UDP' if packet.haslayer(UDP) else 'OTHER',
        'payload_size': len(payload_bytes)
    }
    
    # FIX 3: Ignore base64 in HTTPS traffic
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        src_port = packet[TCP].sport
        
        if dst_port in [443, 8443] or src_port in [443, 8443]:
            signatures_to_check = {k: v for k, v in SIGNATURES.items() if k != "base64_payload"}
        else:
            signatures_to_check = SIGNATURES
    else:
        signatures_to_check = SIGNATURES
    
    # ========== SIGNATURE MATCHING ==========
    total_score = 0
    matched_signatures = []
    matched_categories = set()
    
    for name, sig in signatures_to_check.items():
        if re.search(sig["regex"], payload_formatted, re.IGNORECASE):
            total_score += sig["score"]
            matched_signatures.append(name)
            matched_categories.add(sig["category"])
    
    # ========== PROTOCOL-LEVEL ANALYSIS ==========
    anomalies, protocol_score = analyse_protocol_behavior(packet)
    total_score += protocol_score
    
    # ========== STORE FOR PANDAS ANALYSIS ==========
    packet_info.update({
        'threat_score': total_score,
        'threat_level': 'critical' if total_score >= ALERT_THRESHOLD else ('warning' if total_score > 0 else 'ok'),
        'signatures': ','.join(matched_signatures) if matched_signatures else 'none',
        'categories': ','.join(matched_categories) if matched_categories else 'none',
        'anomalies': ','.join(anomalies) if anomalies else 'none'
    })
    packet_data.append(packet_info)
    
    # ========== THREAT RESPONSE ==========
    if total_score == 0 and not anomalies:
        # Don't print OK messages to reduce console spam
        return {"status": "ok", "packet_info": packet_info}
    
    if total_score < ALERT_THRESHOLD:
        print(f"\033[93m[WARNING] Score={total_score} | {matched_signatures} | {anomalies}\033[0m")
        return {"status": "warning", "score": total_score, "signatures": matched_signatures, 
                "anomalies": anomalies, "packet_info": packet_info}
    
    # CRITICAL ALERT
    print(f"\033[91m[🚨 CRITICAL ALERT 🚨] Score={total_score}\033[0m")
    print(f"  Signatures: {matched_signatures}")
    print(f"  Anomalies: {anomalies}")
    print(f"  {packet_info['src_ip']}:{packet_info['src_port']} → {packet_info['dst_ip']}:{packet_info['dst_port']}")
    
    log_alert(payload_formatted, total_score, ', '.join(matched_signatures), packet_info, anomalies)
    
    return {"status": "critical", "score": total_score, "signatures": matched_signatures,
            "anomalies": anomalies, "packet_info": packet_info, "payload": payload_formatted[:200]}

# ========== IMPROVEMENT 5: REPORT GENERATION ==========
def generate_report():
    """Generate comprehensive analysis report using pandas"""
    if not packet_data:
        return {"error": "No packets analyzed yet"}
    
    df = pd.DataFrame(packet_data)
    
    report = {
        'generated_at': datetime.now().isoformat(),
        'summary': {
            'total_packets': len(df),
            'clean_packets': len(df[df['threat_level'] == 'ok']),
            'warnings': len(df[df['threat_level'] == 'warning']),
            'critical_alerts': len(df[df['threat_level'] == 'critical']),
            'total_threat_score': int(df['threat_score'].sum()),
            'avg_payload_size': int(df['payload_size'].mean())
        },
        'top_threats': {
            'sources': df[df['threat_score'] > 0]['src_ip'].value_counts().head(10).to_dict(),
            'destinations': df[df['threat_score'] > 0]['dst_ip'].value_counts().head(10).to_dict(),
            'signature_frequency': df[df['signatures'] != 'none']['signatures'].value_counts().head(10).to_dict(),
            'category_distribution': {}
        },
        'protocol_analysis': {
            'distribution': df['protocol'].value_counts().to_dict(),
            'avg_score_by_protocol': df.groupby('protocol')['threat_score'].mean().to_dict()
        },
        'timeline': {
            'hourly_threats': df[df['threat_score'] > 0].groupby(
                df['timestamp'].dt.hour
            ).size().to_dict()
        }
    }
    
    all_categories = []
    for cats in df[df['categories'] != 'none']['categories']:
        all_categories.extend(cats.split(','))
    if all_categories:
        from collections import Counter
        report['top_threats']['category_distribution'] = dict(Counter(all_categories).most_common(5))
    
    with open(REPORT_FILE, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n📊 Report generated: {REPORT_FILE}")
    return report

# ========== IMPROVEMENT 6: THREADING FOR PERFORMANCE ==========
def packet_handler(packet):
    """Quick capture - just queue it for async processing"""
    if not packet_queue.full():
        packet_queue.put(packet)
    # Removed the else print to reduce console spam

def packet_processor():
    """Separate thread for packet analysis"""
    global is_running
    while is_running:
        try:
            packet = packet_queue.get(timeout=1)
            analyse(packet)
            packet_queue.task_done()
        except:
            continue

# ========== IMPROVEMENT 7: EFFICIENT SCAPY FILTERS ==========
BPF_FILTERS = {
    'all': 'ip',
    'web': 'tcp port 80 or tcp port 443',
    'dns': 'udp port 53',
    'database': 'tcp port 3306 or tcp port 1433 or tcp port 5432',
    'remote': 'tcp port 22 or tcp port 3389 or tcp port 23',
    'suspicious': 'tcp portrange 1024-65535'
}

# FIX 4: Better stop mechanism
def stop_dpi():
    """Stop the DPI capture properly"""
    global is_running
    print("\n🛑 Stopping DPI...")
    is_running = False
    
    # Wait for queue to empty
    if not packet_queue.empty():
        print("⏳ Processing remaining packets...")
        packet_queue.join()
    
    generate_report()
    print("✅ DPI stopped successfully")

def start_dpi(iface="ens33", packet_count=0, filter_name='all', callback=None):
    """Launch DPI with optimized filtering and threading"""
    global is_running, sniff_thread
    is_running = True
    
    # Start analysis thread
    processor_thread = threading.Thread(target=packet_processor, daemon=True)
    processor_thread.start()
    
    bpf_filter = BPF_FILTERS.get(filter_name, 'ip')
    
    print(f"\n🔵 DPI Started")
    print(f"   Interface: {iface}")
    print(f"   Filter: {filter_name} ({bpf_filter})")
    print(f"   Packet limit: {packet_count if packet_count > 0 else 'unlimited'}")
    print(f"   Threat threshold: {ALERT_THRESHOLD}")
    print(f"   Queue size: {packet_queue.maxsize}")
    print("-" * 50)
    
    try:
        # FIX 5: Add stop_filter to properly stop sniffing
        sniff(
            iface=iface,
            prn=packet_handler,
            filter=bpf_filter,
            store=0,
            count=packet_count,
            stop_filter=lambda x: not is_running  # Stop when is_running becomes False
        )
    except KeyboardInterrupt:
        print("\n\n🛑 DPI Stopped by user")
    finally:
        is_running = False
        print("\n📊 Generating final report...")
        generate_report()
        print("✅ DPI session complete")

# ========== PCAP FILE ANALYSIS ==========
def analyse_pcap_file(pcap_file, callback=None):
    """Analyse a PCAP file instead of live traffic"""
    print("\n" + "="*60)
    print(f"📂 Analyse du fichier PCAP: {pcap_file}")
    print("="*60)
    
    try:
        print("⏳ Chargement des paquets...")
        packets = rdpcap(pcap_file)
        total = len(packets)
        print(f"✅ {total} paquets chargés\n")
        
        threats_found = 0
        warnings_found = 0
        
        for i, packet in enumerate(packets, 1):
            if i % 100 == 0 or i == total:
                print(f"Progress: {i}/{total} paquets analysés...", end='\r')
            
            result = analyse(packet)
            
            if result:
                if result['status'] == 'critical':
                    threats_found += 1
                elif result['status'] == 'warning':
                    warnings_found += 1
                
                if callback:
                    callback(result)
        
        print("\n" + "="*60)
        print("📊 ANALYSE TERMINÉE")
        print("="*60)
        print(f"Total paquets analysés: {total}")
        print(f"🚨 Alertes critiques: {threats_found}")
        print(f"⚠️  Avertissements: {warnings_found}")
        print(f"✅ Paquets sains: {total - threats_found - warnings_found}")
        print("="*60)
        
        print("\n📊 Génération du rapport détaillé...")
        report = generate_report()
        print(f"✅ Rapport sauvegardé dans: {REPORT_FILE}")
        print(f"✅ Logs sauvegardés dans: {LOGFILE}")
        
        return report
        
    except FileNotFoundError:
        print(f"❌ Fichier non trouvé: {pcap_file}")
        return None
    except Exception as e:
        print(f"❌ Erreur lors de l'analyse: {e}")
        import traceback
        traceback.print_exc()
        return None

# ========== MAIN EXECUTION ==========
if __name__ == "__main__":
    print("="*60)
    print("🛡️  Deep Packet Inspection Tool")
    print("="*60)
    
    # Check if analyzing a PCAP file
    if len(sys.argv) > 1 and (sys.argv[1].endswith('.pcap') or sys.argv[1].endswith('.pcapng')):
        pcap_file = sys.argv[1]
        print(f"Mode: Analyse de fichier PCAP")
        print(f"Fichier: {pcap_file}\n")
        analyse_pcap_file(pcap_file)
    else:
        # Live capture mode
        iface = sys.argv[1] if len(sys.argv) > 1 else "ens33"
        filter_type = sys.argv[2] if len(sys.argv) > 2 else "all"
        
        print(f"Mode: Capture en temps réel")
        print(f"Interface: {iface}")
        print(f"Filtre: {filter_type}\n")
        
        try:
            start_dpi(iface=iface, filter_name=filter_type)
        except PermissionError:
            print("❌ Error: Root privileges required for packet capture")
            print("   Run with: sudo python3 dpi_improved.py")
        except Exception as e:
            print(f"❌ Error: {e}")
