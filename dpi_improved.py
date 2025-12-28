from scapy.all import sniff, Raw, IP, TCP, UDP, DNS, ICMP
import re
from datetime import datetime
import base64
import string
import pandas as pd
import json
import threading
from queue import Queue
from collections import defaultdict
import os

# ========== CONFIGURATION ==========
SIGNATURE_FILE = "signatures.json"
LOGFILE = "dpi_alerts.log"
REPORT_FILE = "dpi_report.json"

# ========== IMPROVEMENT 1: Smart Signature Loading ==========
def load_signatures(filepath=SIGNATURE_FILE):
    """Load signatures from JSON file with validation and port filtering"""
    try:
        if not os.path.exists(filepath):
            print(f"⚠️  Warning: {filepath} not found, using default signatures")
            return get_default_signatures()
        
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        signatures = {}
        enabled_count = 0
        disabled_count = 0
        
        for sig_id, sig_data in data.get('signatures', {}).items():
            if sig_data.get('enabled', True):
                signatures[sig_id] = {
                    'regex': sig_data['regex'],
                    'score': sig_data['score'],
                    'category': sig_data['category'],
                    'severity': sig_data.get('severity', 'medium'),
                    'name': sig_data.get('name', sig_id),
                    'exclude_ports': sig_data.get('exclude_ports', [])
                }
                enabled_count += 1
            else:
                disabled_count += 1
        
        alert_threshold = data.get('alert_threshold', 5)
        
        print(f"✅ Loaded {enabled_count} signatures from {filepath}")
        if disabled_count > 0:
            print(f"   ({disabled_count} signatures disabled)")
        
        return signatures, alert_threshold
    
    except json.JSONDecodeError as e:
        print(f"❌ Error parsing {filepath}: {e}")
        print("   Using default signatures")
        return get_default_signatures()
    except Exception as e:
        print(f"❌ Error loading signatures: {e}")
        return get_default_signatures()

def get_default_signatures():
    """Fallback default signatures if JSON fails"""
    return {
        "sql_injection": {
            "regex": r"(union\s+select|or\s+1=1|;\s*drop\s+table)",
            "score": 7,
            "category": "injection_attack",
            "severity": "critical",
            "name": "SQL Injection",
            "exclude_ports": []
        }
    }, 5

# Load signatures globally
SIGNATURES, ALERT_THRESHOLD = load_signatures()

def reload_signatures():
    """Reload signatures from JSON (can be called at runtime)"""
    global SIGNATURES, ALERT_THRESHOLD
    SIGNATURES, ALERT_THRESHOLD = load_signatures()
    print(f"🔄 Signatures reloaded. Active: {len(SIGNATURES)}, Threshold: {ALERT_THRESHOLD}")
    return len(SIGNATURES)

# ========== PACKET DATA STORAGE ==========
packet_data = []
packet_stats = {
    'syn_count': defaultdict(int),
    'dns_queries': defaultdict(int),
    'upload_sizes': defaultdict(int),
    'connection_attempts': defaultdict(int)  # NEW: Track connection patterns
}

# ========== PERFORMANCE OPTIMIZATION ==========
packet_queue = Queue(maxsize=1000)
is_running = False

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

# ========== IMPROVEMENT 2: Enhanced Protocol Analysis ==========
def analyse_protocol_behavior(packet):
    """Detect protocol-level anomalies and exfiltration attempts"""
    anomalies = []
    score_bonus = 0
    
    # TCP Analysis
    if packet.haslayer(TCP):
        src_ip = packet[IP].src if packet.haslayer(IP) else 'unknown'
        dst_port = packet[TCP].dport
        
        # SYN flood detection
        if packet[TCP].flags == 'S':
            packet_stats['syn_count'][src_ip] += 1
            if packet_stats['syn_count'][src_ip] > 100:  # Increased threshold
                anomalies.append("potential_syn_flood")
                score_bonus += 5
        
        # Sensitive port access
        sensitive_ports = {
            22: "SSH", 23: "Telnet", 3389: "RDP", 
            445: "SMB", 1433: "MSSQL", 3306: "MySQL"
        }
        if dst_port in sensitive_ports:
            anomalies.append(f"sensitive_port:{sensitive_ports[dst_port]}")
            score_bonus += 2
            
        # Port scanning detection (NEW)
        packet_stats['connection_attempts'][src_ip] += 1
        if packet_stats['connection_attempts'][src_ip] > 50:
            anomalies.append("potential_port_scan")
            score_bonus += 4
    
    # DNS Analysis - Tunneling Detection
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
        try:
            query = packet[DNS].qd.qname.decode()
            src_ip = packet[IP].src if packet.haslayer(IP) else 'unknown'
            
            # Only flag VERY long queries (reduced false positives)
            if len(query) > 80:  # Increased from 50
                anomalies.append(f"dns_tunneling_length:{len(query)}")
                score_bonus += 7
            
            # Track DNS query frequency
            packet_stats['dns_queries'][src_ip] += 1
            if packet_stats['dns_queries'][src_ip] > 200:  # Increased threshold
                anomalies.append("excessive_dns_queries")
                score_bonus += 4
        except:
            pass
    
    # ICMP Tunneling - Data in ping packets
    if packet.haslayer(ICMP) and packet.haslayer(Raw):
        payload_size = len(packet[Raw].load)
        if payload_size > 100:  # Increased from 56 for real threats
            anomalies.append(f"icmp_exfiltration:{payload_size}b")
            score_bonus += 6
    
    # Large upload detection (potential exfiltration)
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport in [80, 443, 8080]:  # HTTP/HTTPS
            payload_size = len(packet[Raw].load)
            if payload_size > 50000:  # Increased from 10KB to 50KB
                src_ip = packet[IP].src if packet.haslayer(IP) else 'unknown'
                packet_stats['upload_sizes'][src_ip] += payload_size
                anomalies.append(f"large_upload:{payload_size//1000}KB")
                score_bonus += 5
    
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

# ========== IMPROVEMENT 3: Smart Packet Analysis ==========
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
    
    # ========== SIGNATURE MATCHING WITH PORT EXCLUSIONS ==========
    total_score = 0
    matched_signatures = []
    matched_categories = set()
    
    dst_port = packet_info['dst_port']
    src_port = packet_info['src_port']
    
    for name, sig in SIGNATURES.items():
        # Check port exclusions (both source and destination)
        exclude_ports = sig.get('exclude_ports', [])
        if dst_port != 'N/A' and dst_port in exclude_ports:
            continue
        if src_port != 'N/A' and src_port in exclude_ports:
            continue
        
        # Match signature
        try:
            if re.search(sig["regex"], payload_formatted, re.IGNORECASE):
                total_score += sig["score"]
                matched_signatures.append(name)
                matched_categories.add(sig["category"])
        except re.error:
            # Skip malformed regex
            continue
    
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
    
    # ========== IMPROVEMENT 4: Better Console Output ==========
    if total_score == 0 and not anomalies:
        # Only print every 100 clean packets to reduce spam
        if len(packet_data) % 100 == 0:
            print(f"[OK] {len(packet_data)} packets analyzed... (last: {packet_info['src_ip']} → {packet_info['dst_ip']})")
        return {"status": "ok", "packet_info": packet_info}
    
    if total_score < ALERT_THRESHOLD:
        print(f"\033[93m[⚠️  WARNING] Score={total_score} | {', '.join(matched_signatures[:3])} | {packet_info['src_ip']} → {packet_info['dst_ip']}\033[0m")
        return {"status": "warning", "score": total_score, "signatures": matched_signatures, 
                "anomalies": anomalies, "packet_info": packet_info}
    
    # CRITICAL ALERT
    print(f"\n\033[91m{'='*60}\033[0m")
    print(f"\033[91m🚨 CRITICAL ALERT 🚨 Score={total_score}\033[0m")
    print(f"\033[91m{'='*60}\033[0m")
    print(f"  Signatures: {', '.join(matched_signatures)}")
    if anomalies:
        print(f"  Anomalies: {', '.join(anomalies)}")
    print(f"  {packet_info['src_ip']}:{packet_info['src_port']} → {packet_info['dst_ip']}:{packet_info['dst_port']}")
    print(f"\033[91m{'='*60}\033[0m\n")
    
    log_alert(payload_formatted, total_score, ', '.join(matched_signatures), packet_info, anomalies)
    
    return {"status": "critical", "score": total_score, "signatures": matched_signatures,
            "anomalies": anomalies, "packet_info": packet_info, "payload": payload_formatted[:200]}

# ========== REPORT GENERATION ==========
def generate_report():
    """Generate comprehensive analysis report using pandas"""
    if not packet_data:
        return {"error": "No packets analyzed yet"}
    
    df = pd.DataFrame(packet_data)
    
    # Calculate statistics
    total_packets = len(df)
    clean = len(df[df['threat_level'] == 'ok'])
    warnings = len(df[df['threat_level'] == 'warning'])
    critical = len(df[df['threat_level'] == 'critical'])
    
    report = {
        'generated_at': datetime.now().isoformat(),
        'configuration': {
            'alert_threshold': ALERT_THRESHOLD,
            'active_signatures': len(SIGNATURES),
            'signature_file': SIGNATURE_FILE
        },
        'summary': {
            'total_packets': total_packets,
            'clean_packets': clean,
            'clean_percentage': round((clean/total_packets)*100, 2),
            'warnings': warnings,
            'warning_percentage': round((warnings/total_packets)*100, 2),
            'critical_alerts': critical,
            'critical_percentage': round((critical/total_packets)*100, 2),
            'total_threat_score': int(df['threat_score'].sum()),
            'avg_threat_score': round(df['threat_score'].mean(), 2),
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
            'avg_score_by_protocol': df.groupby('protocol')['threat_score'].mean().round(2).to_dict()
        },
        'timeline': {
            'hourly_threats': df[df['threat_score'] > 0].groupby(
                df['timestamp'].dt.hour
            ).size().to_dict()
        }
    }
    
    # Category analysis
    all_categories = []
    for cats in df[df['categories'] != 'none']['categories']:
        all_categories.extend(cats.split(','))
    if all_categories:
        from collections import Counter
        report['top_threats']['category_distribution'] = dict(Counter(all_categories).most_common(5))
    
    # Save report
    with open(REPORT_FILE, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n📊 Report generated: {REPORT_FILE}")
    print(f"   Total packets: {total_packets}")
    print(f"   Clean: {clean} ({report['summary']['clean_percentage']}%)")
    print(f"   Warnings: {warnings} ({report['summary']['warning_percentage']}%)")
    print(f"   Critical: {critical} ({report['summary']['critical_percentage']}%)")
    
    return report

# ========== THREADING FOR PERFORMANCE ==========
def packet_handler(packet):
    """Quick capture - just queue it for async processing"""
    if not packet_queue.full():
        packet_queue.put(packet)

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

# ========== EFFICIENT SCAPY FILTERS ==========
BPF_FILTERS = {
    'all': 'ip',
    'web': 'tcp port 80 or tcp port 443',
    'dns': 'udp port 53',
    'database': 'tcp port 3306 or tcp port 1433 or tcp port 5432',
    'remote': 'tcp port 22 or tcp port 3389 or tcp port 23',
    'suspicious': 'tcp portrange 1024-65535'
}

def start_dpi(iface="ens33", packet_count=0, filter_name='all', callback=None):
    """Launch DPI with optimized filtering and threading"""
    global is_running
    is_running = True
    
    # Reload signatures before starting
    reload_signatures()
    
    # Start analysis thread
    processor_thread = threading.Thread(target=packet_processor, daemon=True)
    processor_thread.start()
    
    # Get BPF filter
    bpf_filter = BPF_FILTERS.get(filter_name, 'ip')
    
    print(f"\n🔵 DPI Started")
    print(f"   Interface: {iface}")
    print(f"   Filter: {filter_name} ({bpf_filter})")
    print(f"   Packet limit: {packet_count if packet_count > 0 else 'unlimited'}")
    print(f"   Signatures: {len(SIGNATURES)} active")
    print(f"   Threat threshold: {ALERT_THRESHOLD}")
    print("-" * 50)
    
    try:
        sniff(
            iface=iface,
            prn=packet_handler,
            filter=bpf_filter,
            store=0,
            count=packet_count
        )
    except KeyboardInterrupt:
        print("\n\n🛑 DPI Stopped by user")
    finally:
        is_running = False
        print("\n📊 Generating final report...")
        generate_report()
        print("✅ DPI session complete")

def stop_dpi():
    """Stop the DPI capture"""
    global is_running
    is_running = False
    generate_report()

# ========== PCAP FILE ANALYSIS ==========
def analyse_pcap_file(pcap_file, callback=None):
    """Analyse a PCAP file instead of live traffic"""
    from scapy.all import rdpcap
    
    print("\n" + "="*60)
    print(f"📂 Analyse du fichier PCAP: {pcap_file}")
    print("="*60)
    
    reload_signatures()
    
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
    import sys
    
    print("="*60)
    print("🛡️  Deep Packet Inspection Tool - Optimized")
    print("="*60)
    
    if len(sys.argv) > 1 and (sys.argv[1].endswith('.pcap') or sys.argv[1].endswith('.pcapng')):
        pcap_file = sys.argv[1]
        print(f"Mode: Analyse de fichier PCAP")
        print(f"Fichier: {pcap_file}\n")
        analyse_pcap_file(pcap_file)
    else:
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
