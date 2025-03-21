# 🛡️ Ethical Hacking & Penetration Test 2 – Python Programming for Hacking

Benvenuto/a in questo repository, che raccoglie una collezione di script Python realizzati per il corso **Ethical Hacking and Penetration Test 2 – Python Programming for Hacking**, organizzato da UNINT – Università degli Studi Internazionali di Roma.

Questi script sono progettati per introdurre e approfondire tecniche di hacking etico, analisi di vulnerabilità, scansione di rete e test di penetrazione.

---

## 🎯 Obiettivi del Corso

- Sviluppare script personalizzati in Python per test di sicurezza
- Automatizzare attività di penetration testing
- Analizzare traffico di rete e comportamenti sospetti
- Simulare attacchi (ARP spoofing, sniffing DNS, attacchi brute-force e SQL injection)
- Interrogare e analizzare CVE con API pubbliche

---

## 📁 Struttura del Progetto

```text
.
├── pen_test/               # Strumenti per sniffing, spoofing e scansione rete
├── port scan/              # Scanner TCP e analizzatori di porte web
├── read_write_log/         # Script per gestione e filtraggio di log
├── vulnerability/          # Dimostrazioni di vulnerabilità e exploit
```

---

## 🔍 Contenuto Principale

### 📡 pen_test/
- `arp_spoofing.py` – Simula attacco ARP man-in-the-middle
- `dns_sniffer_pro.py` – Sniffer DNS con logging e rilevamento domini sospetti
- `network_scanner.py` – Scansione di rete con pacchetti SYN e sweep ICMP
- `nmap_port_scanner.py` – Wrapper Python per Nmap
- `sniffer_ARP.py`, `sniffer_DNS.py`, `sniffing.py` – Script passivi di intercettazione traffico

### 🔓 port scan/
- `port_scanner.py`, `port_request.py` – Scanner TCP con analisi HTTP
- `resolve_domain.py` – Risoluzione DNS da dominio

### 🧾 read_write_log/
- `read_write_log.py` – Script per filtrare messaggi di log rilevanti (ERROR, WARNING, CRITICAL)

### ⚠️ vulnerability/
- `brute_force.py`, `brute_force_demo.py` – Simulazione attacco a forza bruta
- `check_password.py` – Verifica password con HIBP (API HaveIBeenPwned)
- `scanner_cve.py`, `vulnerability_api.py`, `new_vuln_api.py` – Interrogazione CVE e CPE da file o API NVD
- `sql_injection/` – Simulazione SQLi su database SQLite con versioni insicure e sicure del login
- `test_command_injection.py`, `test_traversal.py` – Esempi di attacchi command injection e directory traversal

---

## ⚙️ Requisiti

- **Python 3.8+**
- Librerie:
  - `scapy`
  - `nmap`
  - `requests`
  - `sqlite3` (built-in)
  - `subprocess`, `socket`, `itertools`, `hashlib` (built-in)

Installa le dipendenze principali con:

```bash
pip install scapy python-nmap requests
```

---

## ⚠️ Note importanti

- Alcuni script richiedono **permessi di root/amministratore**, soprattutto per sniffing e spoofing.
- Evita di utilizzare questi strumenti in ambienti di produzione o reti non autorizzate.  
  Sono destinati **esclusivamente a scopo formativo e didattico**.

---

## 📚 Collegamento al corso

📌 **Corso:** Ethical Hacking and Penetration Test 2  
🏛️ **Organizzato da:** Scuola di Alta Formazione – UNINT  
📆 **Durata:** 20 ore  

### Argomenti trattati:
- Introduzione a Python per l'hacking etico (4h)
- Programmare test di penetrazione (4h)
- Analisi di vulnerabilità (4h)
- Librerie e framework di hacking (6h)
- Best practices ed etica (2h)

## 📜 LICENSE

Questo progetto è concesso in licenza sotto la Licenza MIT. Vedi il file [LICENSE](LICENSE) per i dettagli.

## ⚖️ Disclaimer

> Questo progetto ha finalità **esclusivamente educative**.  
> L'autore declina ogni responsabilità per un uso improprio degli script contenuti.

