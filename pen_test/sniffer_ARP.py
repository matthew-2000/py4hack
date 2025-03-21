from scapy.all import ARP, sniff  # Importa la libreria per lavorare con pacchetti di rete

# Funzione che verrà chiamata ogni volta che un pacchetto viene intercettato
def arp_display(pkt):
    # Controlla se il pacchetto è di tipo ARP e se è una richiesta (non una risposta)
    if pkt.haslayer(ARP) and pkt[ARP].op == 1:
        # Estrae e mostra l'IP che sta facendo la richiesta e quello che sta cercando
        print(f"[+] Richiesta ARP: il dispositivo {pkt[ARP].psrc} sta cercando {pkt[ARP].pdst}")

# Avvia lo "sniffing", cioè l'ascolto dei pacchetti sulla rete
print("[*] In ascolto delle richieste ARP... (premi CTRL+C per fermare)")
sniff(filter="arp", prn=arp_display, store=0)