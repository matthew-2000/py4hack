from scapy.all import *

# Creazione di un pacchetto ICMP per il test
# IP() crea un pacchetto IP. L'argomento 'dst' specifica l'indirizzo di destinazione del pacchetto.
# In questo caso, l'indirizzo di destinazione è "8.8.8.8", che è uno dei server DNS pubblici di Google.
packet = IP(dst="8.8.8.8")/ICMP()
# ICMP() crea un pacchetto ICMP (Internet Control Message Protocol), che viene utilizzato per inviare messaggi di errore e operazioni di rete.
# Il simbolo '/' viene utilizzato per concatenare il pacchetto IP con il pacchetto ICMP.

# send() invia il pacchetto creato sulla rete.
send(packet)

# Stampa un messaggio di conferma che il pacchetto ICMP è stato inviato.
print("Pacchetto ICMP inviato!")
