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

class BaseIRR:
    def __init__(self):
        pass

    def printar(self, command, result):
        print("="*50)
        print(f"Informações IRR com o comando: {command}:")
        print("="*50)
        print(result)
        print("\n" + "="*50 + "\n")

class IRR(BaseIRR):
    def __init__(self, as_input, ips):
        super().__init__()
        self.as_input = as_input
        self.ips = ips

    def execute_irr(self):
        while True:
            decisao = int(input('Você deseja pesquisar o IRR por bloco de IP? 1 - Sim, 2 - Não: '))

            if decisao == 1:
                for index, item in enumerate(self.ips, start=1):
                    print(f"{index}: {item}")
                
                # Loop até que o usuário forneça um número válido
                while True:
                    id_Ip = input('\nDigite o número correspondente ao IP: ')
                    if not id_Ip.isdigit():
                        print("Por favor, insira apenas números.")
                        continue
                    id_Ip = int(id_Ip)
                    if id_Ip < 1 or id_Ip > len(self.ips):
                        print("Por favor, insira um número dentro do intervalo válido.")
                    else:
                        break  # Sai do loop enquanto o número for válido
                
                commando1 = f"whois -h whois.radb.net {self.ips[id_Ip - 1]}"
                resultado1 = os.popen(commando1).read()

                print("="*50)
                print(f"Informações IRR por bloco com o comando: {commando1}:")
                print("="*50)
                print(resultado1)
                print("\n" + "="*50 + "\n")

            elif decisao == 2:
                command = f"whois -h whois.radb.net AS{self.as_input}"
                result = os.popen(command).read()
                self.printar(command, result)
                break  # Sai do loop while

            else:
                print("Comando não encontrado, prosseguindo com as outras informações: ")

def extract_ips(result):
    ipv4_cidr_pattern = re.compile(r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\/\d+)')
    ipv6_cidr_pattern = re.compile(r'([\da-fA-F:]+(?:::[\da-fA-F]*)?)/(3[2-9]|[4-9]\d|1\d{2}|12[0-8])')

    ips = []
    ipv6_cidrs = ipv6_cidr_pattern.findall(result)
    for ipv6_cidr in ipv6_cidrs:
        ipv6_cidr_str = f"{ipv6_cidr[0]}/{ipv6_cidr[1]}"
        ips.append(ipv6_cidr_str)
    ips.extend(ipv4_cidr_pattern.findall(result))

    return ips

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

def asinfo():
    resposta = str(input("Você deseja verificar o AS-SET? Sim ou Não? "))
    
    if resposta.lower() == "sim":
        asset = input("Então, digite o AS-SET: ")


        command = f"whois -h whois.radb.net {asset}"
        result = os.popen(command).read()

        print("="*50)
        print(f"Informações de {command}:")
        print("="*50)

        print(result)

        print("\n" + "="*50 + "\n")
        
    elif resposta.lower() == "não":
        print("Ok, retornando para outras informações")
        
    else:
        print("Você digitou algo errado.")



if __name__ == "__main__":
    as_input = input("Digite o número AS: ")
    ips = whoismet(as_input)
    irr_instance = IRR(as_input, ips)
    irr_instance.execute_irr()
    obter_informacoes(as_input)
    asinfo()