from scapy.all import IP, TCP, ICMP, sr1, sr, send

# Importa i moduli necessari da scapy

# Funzione per eseguire una scansione SYN
def syn_scan(target_ip, target_ports):
    # Itera sulla lista delle porte target
    for port in target_ports:
        # Crea un pacchetto SYN
        syn_packet = IP(dst=target_ip)/TCP(dport=port, flags='S')
        # Invia il pacchetto e riceve la risposta
        response = sr1(syn_packet, timeout=1, verbose=0)
        
        # Controlla se abbiamo ricevuto una risposta
        if response:
            # Controlla se il flag SYN-ACK è impostato nella risposta
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                print(f"Porta {port} è aperta su {target_ip}")
                # Invia un pacchetto RST per chiudere la connessione
                rst_packet = IP(dst=target_ip)/TCP(dport=port, flags='R')
                send(rst_packet, verbose=0)
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                print(f"Porta {port} è chiusa su {target_ip}")
        else:
            print(f"Porta {port} è filtrata o l'host è giù su {target_ip}")

# Funzione per eseguire un ping sweep ICMP
def icmp_ping_sweep(target_network):
    # Crea un pacchetto IP con richiesta ICMP
    icmp_packet = IP(dst=target_network)/ICMP()
    # Invia il pacchetto e riceve la risposta
    responses, no_responses = sr(icmp_packet, timeout=2, verbose=0)
    
    # Itera sulle risposte
    for response in responses:
        print(f"Host {response[1].src} è attivo")

# Funzione principale
def main():
    # Definisce l'IP target e le porte per la scansione SYN
    target_ip = "192.168.1.1"
    target_ports = [22, 80, 443]  # Esempio di porte da scansionare
    syn_scan(target_ip, target_ports)
    icmp_ping_sweep("192.168.1.0/24")

if __name__ == "__main__":
    main()