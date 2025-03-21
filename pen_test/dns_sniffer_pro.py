import os
import platform
from scapy.all import sniff, DNS, IP
from datetime import datetime

# Lista di domini sospetti (può essere estesa)
SUSPICIOUS_KEYWORDS = ["xn--", ".xyz", ".top", ".cn", "dark", "tor", "malware", "hidden"]

# File di log
LOG_FILE = "dns_sniffer_log.txt"

# Determina se il pacchetto DNS è sospetto
def is_suspicious(domain):
    domain = domain.lower()
    return any(keyword in domain for keyword in SUSPICIOUS_KEYWORDS)

# Salva le info su file
def log_entry(entry):
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

# Funzione principale per processare i pacchetti DNS
def dns_sniffer(packet):
    TARGET_IP = "192.168.1.120"  # IP della VM
    if packet.haslayer(DNS) and packet[IP].src == TARGET_IP:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_source = packet[IP].src
        domain_name = packet[DNS].qd.qname.decode() if packet[DNS].qd else "<unknown>"

        # qr=0 → richiesta | qr=1 → risposta
        if packet[DNS].qr == 0:
            info = f"[{timestamp}] [REQ] {ip_source} → {domain_name}"
        else:
            # Risposta con IP (se presente)
            resolved_ips = []
            if packet[DNS].an:
                for i in range(packet[DNS].ancount):
                    r = packet[DNS].an[i]
                    if hasattr(r, "rdata") and isinstance(r.rdata, str):
                        resolved_ips.append(r.rdata)
            ip_str = ", ".join(resolved_ips) if resolved_ips else "?"
            info = f"[{timestamp}] [RES] {ip_source} ← {domain_name} ({ip_str})"

        # Controlla se sospetto
        if is_suspicious(domain_name):
            info += " ⚠️ [SOSPETTO]"

        print(info)
        log_entry(info)

# Verifica i permessi
def check_privileges():
    system = platform.system()
    if system == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0

# Entry point
if __name__ == "__main__":
    print("[*] Avvio DNS Sniffer multipiattaforma")
    if not check_privileges():
        print("[!] Devi eseguire questo script come amministratore (su macOS) o da terminale con privilegi (su Windows).")
        exit(1)

    print("[*] In ascolto del traffico DNS (UDP 53)... Premi CTRL+C per interrompere.")
    try:
        sniff(filter="udp port 53", prn=dns_sniffer, store=0)
    except KeyboardInterrupt:
        print("\n[!] Intercettazione interrotta dall'utente.")
    except Exception as e:
        print(f"[!] Errore: {e}")
