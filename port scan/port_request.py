import socket
import requests

def scan_ports(host, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def analyze_responses(host, open_ports):
    for port in open_ports:
        try:
            url = f"http://{host}:{port}"
            response = requests.get(url)
            print(f"Porta {port} - Status Code: {response.status_code}")
            print(f"Risposta: {response.text[:100]}...")  # Mostra solo i primi 100 caratteri della risposta
        except requests.exceptions.RequestException as e:
            print(f"Porta {port} - Errore: {e}")


host = "google.com"  # Sostituisci con l'host del server che vuoi analizzare
start_port = 80
end_port = 81

print(f"Scansione delle porte aperte su {host}...")
open_ports = scan_ports(host, start_port, end_port)
print(f"Porte aperte trovate: {open_ports}")

print("Analisi delle risposte dalle porte aperte...")
analyze_responses(host, open_ports)