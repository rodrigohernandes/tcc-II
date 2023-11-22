import requests
from colorama import Fore, Style, init
from .utils.pulse_info import alv_pulse_info
from .utils.url_list import alv_url_list
init(autoreset=True)

def alv_get_ip(api, ip_addr):

    response_general = requests.get(f'https://otx.alienvault.com/api/v1/indicator/IPv4/{ip_addr}/', 
        headers={
            'X-OTX-API-KEY': api
        }).json()
    response_malware = requests.get(f'https://otx.alienvault.com/api/v1/indicator/IPv4/{ip_addr}/malware', 
        headers={
            'X-OTX-API-KEY': api
        }).json()
    response_url_list = requests.get(f'https://otx.alienvault.com/api/v1/indicator/IPv4/{ip_addr}/url_list', 
        headers={
            'X-OTX-API-KEY': api
        }).json()

    try:
        print(Fore.MAGENTA + Style.BRIGHT + '\n-=-=-=- OTX Alien Vault -=-=-=-\n')
        print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')

        reputation = response_general["reputation"]
        if reputation < 0:
            reputation = Fore.RED + f"{reputation}"
        else:
            reputation = Fore.GREEN + f"{reputation}"

        print(f'Reputação: {reputation}\n')
        print(f'País: {response_general["country_name"]}')
        print(f'Continente: {response_general["continent_code"]}\n')
        print(f'WHOIS Lookup: {response_general["whois"]}')
        print(f'Autonomous System Number: {response_general["asn"]}')

        if response_general['validation']:
            for i in response_general['validation']:
                if i['source'] == 'whitelist':
                    print('Veredito: ' + Fore.GREEN + f"{i['name']}")

        # ----------------- URL LIST -----------------
        alv_url_list(response_url_list)

        # ----------------- PULSE INFO -----------------
        alv_pulse_info(response_general)

        if response_malware['count'] > 0:
            print(f'\nQuantidade total de malwares identificados: ' + Fore.RED + Style.BRIGHT + f'{response_malware["count"]}')


    except Exception as e:
        print(Fore.RED + Style.BRIGHT + "\n-=-=- ERROR - AlienVault -=-=-")
        print(e)
        print(Fore.RED + Style.BRIGHT + "-=-=- ERROR - AlienVault -=-=-\n")
