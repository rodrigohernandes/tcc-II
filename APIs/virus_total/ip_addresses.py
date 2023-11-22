import requests
from colorama import Fore, Style, init
from .utils.detection_info import detection_info
init(autoreset=True)

def vt_get_ip(api, ip_addr):
    
    response = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip_addr}', 
        headers={
            'x-apikey': api
        }).json()

    try:
        attributes = response['data']['attributes']
        analysis_stats = response['data']['attributes']['last_analysis_stats']
        analysis_results = response['data']['attributes']['last_analysis_results']

        print(Fore.MAGENTA + Style.BRIGHT + '\n\n-=-=-=- VirusTotal -=-=-=-\n')
        print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')

        reputation = attributes["reputation"]
        if reputation < 0:
            reputation = Fore.RED + f"{reputation}"
        else:
            reputation = Fore.GREEN + f"{reputation}"

        print(f'Reputação: {reputation}\n')
        print(f'País: {attributes["country"]}')
        print(f'Continente: {attributes["continent"]}\n')
        print(f'Registro de internet regional: {attributes["regional_internet_registry"]}')
        print(f'Rede: {attributes["network"]}')
        if 'whois' in attributes:
            print(f'WHOIS Lookup: {attributes["whois"]}')
 
        print(f'Autonomous System Owner: {attributes["as_owner"]}')
        print(f'Autonomous System Number: {attributes["asn"]}')
        if "jarm" in attributes:
            print(f'JARM fingerprint: {attributes["jarm"]}\n')

        # ------------------- DETECÇÕES -------------------
        detection_info(attributes, analysis_stats, analysis_results)


    except Exception as e:
        print(Fore.RED + Style.BRIGHT + "-=-=- ERROR - VirusTotal -=-=-")
        print(e)
        print(Fore.RED + Style.BRIGHT + "-=-=- ERROR - VirusTotal -=-=-")
