from scapy.all import sniff, DNS, IP

# Funzione che viene eseguita ogni volta che arriva un pacchetto catturato
def dns_sniffer(packet):
    # Verifica se il pacchetto ha il livello DNS e se è una "richiesta" (qr = 0)
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        # Estrae l'IP sorgente e il nome del sito richiesto
        ip_source = packet[IP].src
        domain_name = packet[DNS].qd.qname.decode()  # qd = query data, qname = nome dominio
        print(f"[DNS] {ip_source} → {domain_name}")

# Avvia lo sniffing dei pacchetti con filtro UDP su porta 53 (quella usata dal DNS)
print("[*] In ascolto del traffico DNS sulla rete... (CTRL+C per interrompere)")
sniff(filter="udp port 53", prn=dns_sniffer, store=0)