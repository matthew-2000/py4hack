import nmap  # Importa la libreria che permette di usare Nmap tramite Python

# Crea un oggetto "scanner", che useremo per fare la scansione
scanner = nmap.PortScanner()

# Indirizzo IP o intervallo di rete da scansionare
# In questo esempio: tutta la rete 192.168.1.x (modificabile in base alla tua rete)
network_range = '172.20.10.0/24'

# Opzioni per la scansione:
# -sS: usa il metodo SYN scan (rapido e spesso non rilevato dai firewall)
# -p1-1000: scansiona le porte dalla 1 alla 1000 (le più comuni)
# -T4: velocità medio-alta
scan_args = '-sS -p1-1000 -T4'

print(f"[*] Inizio della scansione sulla rete: {network_range}")
scanner.scan(hosts=network_range, arguments=scan_args)

# Questo ciclo analizza ogni computer trovato attivo nella rete
for host in scanner.all_hosts():
    print(f"\n[+] Host trovato: {host} ({scanner[host].hostname()})")
    print(f"    Stato: {scanner[host].state()}")  # Stato può essere 'up' (attivo) o 'down' (spento/non raggiungibile)

    # Per ogni protocollo trovato (es. TCP o UDP)
    for proto in scanner[host].all_protocols():
        ports = scanner[host][proto].keys()  # Ottiene le porte trovate
        for port in sorted(ports):
            # Stampa info sulla porta: numero, tipo (tcp/udp), stato (open/closed), nome del servizio (es: http)
            state = scanner[host][proto][port]['state']
            name = scanner[host][proto][port]['name']
            print(f"    Porta {port}/{proto} - {state} - Servizio: {name}")
