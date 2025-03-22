import nmap
import schedule
import time

def scan_ports(host):
    print(f"Starting port scan on {host}...")
    nm = nmap.PortScanner()
    nm.scan(host, '1-1000')
    open_ports = []
    for proto in nm[host].all_protocols():
        ports = nm[host][proto].keys()
        open_ports.extend([port for port in ports if nm[host][proto][port]['state'] == 'open'])
    print(f"Port scan on {host} completed.")
    return open_ports

def job():
    host = '172.20.10.2'  # Replace with the host you want to scan
    print(f"Running scheduled job for host: {host}")
    open_ports = scan_ports(host)
    print(f"Open ports on {host}: {open_ports}")

# Schedule the job to run at 9 AM every day
schedule.every().day.at("11:42").do(job)

print("Scheduler started. Waiting for the scheduled time...")

while True:
    schedule.run_pending()
    time_to_sleep = schedule.idle_seconds()
    if time_to_sleep is None:
        time_to_sleep = 1
    time.sleep(time_to_sleep)