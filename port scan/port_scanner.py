import socket

def port_scan(target_ip, start_port, end_port):
    print(f"Scansione di {target_ip} da porta {start_port} a {end_port}")
    porte = []
    for port in range(start_port, end_port+1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        print(f"Scansione porta {port}")
        result = s.connect_ex((target_ip, port))
        # result = 0 se la connessione ha successo => porta aperta
        if result == 0:
            print(f"[+] Porta {port} aperta")
            porte.append(port)
        else:
            print(f"[-] Porta {port} chiusa")
        s.close()
    return porte

def scrivi_file(porte):
    with open("port_scan_result.txt", "w") as f:
        for porta in porte:
            f.write(f"Porta {porta} aperta\n")

domain = input("Inserisci il dominio da scansionare: ")
ip_address = socket.gethostbyname(domain)
print(f"[+] {domain} risolto in: {ip_address}")

start_port = int(input("Inserisci la porta di inizio: "))
end_port = int(input("Inserisci la porta di fine: "))

porte = port_scan(ip_address, start_port, end_port)
scrivi_file(porte)

print("Scansione completata. Risultati salvati in port_scan_result.txt")