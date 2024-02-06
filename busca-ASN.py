import requests, os
from bs4 import BeautifulSoup

#'whois','peers', 'peers6' adicione na variavel ids= para puxar essas info também


def whoismet(as_number):
    command = f"whois AS{as_number} | grep -E 'autnum:|owner:|inetnum:|ASNumber:|ASName:|ASHandle:'"
    result = os.popen(command).read()

    print("="*50)
    print(f"Informações de {command}:")
    print("="*50)

    print(result)

    print("\n" + "="*50 + "\n")

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
                print(line)
                if 'UPX' in line:
                    print()
        else:
            print("Nenhuma informação encontrada.")

        print("\n" + "="*50 + "\n")

if __name__ == "__main__":
    as_input = input("Digite o número AS: ")
    whoismet(as_input)
    obter_informacoes(as_input)