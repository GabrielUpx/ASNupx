import subprocess
import re
import time
import ipaddress

def extract_ips(result):
    # Expressão regular para encontrar os IPs IPv4
    ipv4_ip_pattern = re.compile(r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}(?:/\d{1,2})?')

    ip_whois = []
    
    ip_whois.extend(ipv4_ip_pattern.findall(result))

    return ip_whois

def extract_asn():
    asn_list = []

    with open('dns_ips.txt', "r") as arquivo:
        for linha in arquivo:
            # Verificar se a linha contém "ASN:" e extrair o número ASN
            if "ASN:" in linha:
                asn = linha.split("ASN:")[1].strip()  # Extrair o número ASN
                asn_list.append(asn)  # Adicionar o ASN à lista
    return asn_list

def readArq():
    ips=[]
    try:
        with open('dns_ips.txt', 'r') as file:
            for line in file:
                ips.extend(extract_ips(line.strip()))
    except FileNotFoundError:
        print("Arquivo 'dns_ips.txt' não encontrado.")
        exit()
    return ips

def buscaASN(asnNumber):
    count = 0
    # Limpa o arquivo antes de escrever nele
    with open('resultado.txt', 'w') as file:
        for asn in asnNumber:
            command = f"whois AS{asn} | grep inetnum:"
            try:          
                count+=1
                if count > 30:
                    count = 0
                    print("Aguardando para continuar as buscas, tempo de aguardo: 3 minutos")
                    waitConsult()
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    response = result.stdout.strip()
                    ips_Asn = extract_ips(response)
                    writeArq_asn(asn,ips_Asn)
                else:
                    print("Command execution failed with error:", result.stderr.strip())
            except subprocess.TimeoutExpired:
                print("Timeout occurred while executing the command")
            except subprocess.CalledProcessError as e:
                print("Command execution failed:", e)
            except Exception as e:
                print("Unexpected error occurred:", e)

def writeArq_asn(ip,response):
    with open('resultado.txt', 'a') as file:
        file.write(f"ASN: {ip} Response: {response}\n\n")
    print("Execução completa.")

def writeArq_ip(ip):
    with open('resultado2_ip.txt', 'a') as file:
        file.write(f"{ip}\n\n")
    
def waitConsult():
    # Define o tempo total de espera em segundos
    tempo_total = 180  # 3 minutos

    # Loop enquanto o tempo total não foi alcançado
    while tempo_total > 0:
        # Mostra a mensagem sobre o tempo restante a cada minuto
        if tempo_total % 60 == 0:
            minutos_restantes = tempo_total // 60
            print(f"Ainda falta(m) {minutos_restantes} minuto(s)...")
                    
        # Espera por 1 segundo
        time.sleep(1)
        # Reduz o tempo total em 1 segundo
        tempo_total -= 1

def comparaIps(enderecosIP):
    ips_asn = []

    # Coleta todos os IPs dos ASN em uma lista
    with open('resultado.txt', "r") as arquivo:
        for linha in arquivo:
            match = re.match(r'.*Response:\s+\[(.*)\]', linha)
            if match:
                ips_comparar = match.group(1).split(', ')
                for ip_cidr in ips_comparar:
                    ip_cidr = ip_cidr.strip(" '")  # Remove espaços e aspas
                    rede = ipaddress.ip_network(ip_cidr, strict=False)
                    for ip in rede:
                        ips_asn.append(str(ip))
    #Limpa o arquivo antes de escrever nele
    with open('resultado2_ip.txt', 'w') as file:

        # Compara cada IP individual com a lista de IPs dos ASN
        for ip in enderecosIP:
            if ip not in ips_asn:
                writeArq_ip(ip)

asn_number = extract_asn()
buscaASN(asn_number)
enderecosIP = readArq()
comparaIps(enderecosIP)