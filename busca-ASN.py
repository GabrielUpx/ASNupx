
import requests, os
from bs4 import BeautifulSoup
import re

#'whois','peers', 'peers6' adicione na variavel ids= para puxar essas info também

def whoismet(as_number):
    command = f"whois AS{as_number} | grep -E 'autnum:|owner:|inetnum:|ASNumber:|ASName:|ASHandle:'"
    result = os.popen(command).read()

    print("="*50)
    print(f"Informações de {command}:")
    print("="*50)

    print(result)

    ips = extract_ips(result)

    print("\n" + "="*50 + "\n")

    return ips

def extract_ips(result):
    # Expressão regular para encontrar os IPs com as máscaras
    ipv4_cidr_pattern = re.compile(r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\/\d+)')
    ipv6_cidr_pattern = re.compile(r'([\da-fA-F:]+(?:::[\da-fA-F]*)?)/(3[2-9]|[4-9]\d|1\d{2}|12[0-8])')

    # Encontre todos os IPs com as máscaras no resultado
    ips = []

    # Encontre todos os IPs IPv6 com as máscaras >= 32 no resultado
    ipv6_cidrs = ipv6_cidr_pattern.findall(result)

    # Adicione os IPs IPv6 à lista ips
    for ipv6_cidr in ipv6_cidrs:
        ipv6_cidr_str = f"{ipv6_cidr[0]}/{ipv6_cidr[1]}"
        ips.append(ipv6_cidr_str)

    # Adicione os IPs IPv4 à lista ips
    ips.extend(ipv4_cidr_pattern.findall(result))

    return ips

def irr(as_number, ips):
    while True:
        decisao = int(input('Você deseja pesquisar o IRR por bloco de IP? 1 - Sim, 2 - Não: '))

        def printar():
            print("="*50)
            print(f"Informações IRR com o comando: {command}:")
            print("="*50)
            print(result)
            print("\n" + "="*50 + "\n")

        if decisao == 1:
            for index, item in enumerate(ips, start=1):
                print(f"{index}: {item}")
            id_Ip = int(input('Digite o número correspondente ao IP: '))
            commando1 = f"whois -h whois.radb.net {ips[id_Ip - 1]}"
            resultado1 = os.popen(commando1).read()

            print("="*50)
            print(f"Informações IRR por bloco com o comando: {commando1}:")
            print("="*50)
            print(resultado1)
            print("\n" + "="*50 + "\n")

        elif decisao == 2:
            command = f"whois -h whois.radb.net AS{as_number}"
            result = os.popen(command).read()
            printar()
            break  # Sai do loop while

        else:
            print("Comando não encontrado, prosseguindo com as outras informações: ")


def obter_informacoes(as_number):
    ids = ['irr', 'prefixes', 'prefixes6'] 

    for section_id in ids:
        url = f"https://bgp.he.net/AS{as_number}#{section_id}"
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        print("="*50)
        print(f"Informações de {url}:")
        print("="*50)

        info_div = soup.find('div', {'id': section_id})

        if info_div:
            for line in info_div.stripped_strings:
                if 'import:' in line:
                    print()
                print(line)
                if 'UPX' in line:
                    print()
        else:
            print("Nenhuma informação encontrada.")

        print("\n" + "="*50 + "\n")

if __name__ == "__main__":
    as_input = input("Digite o número AS: ")
    ips = whoismet(as_input)
    irr(as_input, ips)
    obter_informacoes(as_input)
