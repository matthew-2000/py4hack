import socket

def resolve_domain(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"[+] {domain} risolto in: {ip_address}")
    except socket.gaierror:
        print(f"[-] Impossibile risolvere l'host: {domain}")

# Esempio di utilizzo
resolve_domain("www.google.com")
resolve_domain("www.unisa.it")