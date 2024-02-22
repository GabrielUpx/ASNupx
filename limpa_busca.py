import re

arq0 = "bgp_summary.txt"
arq2 = "resultados_ips.txt"

def extract_ips(result):
    # Expressão regular para encontrar os IPs IPv4
    ipv4_ip_pattern = re.compile(r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}(?:/\d{1,2})?')

    ip_whois = []
    
    ip_whois.extend(ipv4_ip_pattern.findall(result))

    return ip_whois

def readArq():
    global arq0
    ips=[]
    try:
        with open(arq0, 'r') as file:
            for line in file:
                ips.extend(extract_ips(line.strip()))
    except FileNotFoundError:
        print("Arquivo ", arq0 ," não encontrado.")
        exit()
    return ips

def writeArq_ip(ips):
    global arq2
    with open(arq2, 'a') as file:
        for ip in ips:
            file.write(f"IP: {ip}\n\n")

enderecosIP = readArq()
writeArq_ip(enderecosIP)