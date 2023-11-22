import requests
from colorama import Fore, Style, init
from .utils.pulse_info import alv_pulse_info
from time import sleep
init(autoreset=True)

def alv_get_hash(api, hash):

    response_general = requests.get(f'https://otx.alienvault.com/api/v1/indicator/file/{hash}/general', 
    headers={
        'X-OTX-API-KEY': api
    })

    response_analysis = requests.get(f'https://otx.alienvault.com/api/v1/indicator/file/{hash}/analysis', 
    headers={
        'X-OTX-API-KEY': api
    })

    try:
        
        print(Fore.MAGENTA + Style.BRIGHT + '\n-=-=-=- OTX Alien Vault -=-=-=-\n')

        if response_general.status_code != 200 or response_analysis.status_code != 200 or not response_analysis.json()['analysis']:
            print(Fore.RED + Style.BRIGHT + 'Sem dados suficienes sobre o arquivo/hash\n')

        else:
            response_general = response_general.json()
            response_analysis = response_analysis.json()

            print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')

            print(f'Título do tipo: {response_general["type_title"]}')

            file_type = response_analysis['analysis']['info']['results']
            if file_type["file_type"]:
                print(f'Tipo do arquivo: {file_type["file_type"]}')
            if file_type["file_class"]:
                print(f'Título do tipo: {file_type["file_class"]}')


            print(Fore.CYAN + Style.BRIGHT + '\n=== HASHES ===\n')

            print(f'Tipo do hash do IOC: {response_general["type"]}')
            print('Outras hashes deste IOC:')
            hashes = response_analysis['analysis']['info']['results']
            if hashes['md5']:
                print(Fore.YELLOW + Style.BRIGHT + f'  -> MD5: {hashes["md5"]}')

            if hashes['sha1']:
                print(Fore.YELLOW + Style.BRIGHT + f'  -> SHA1: {hashes["sha1"]}')

            if hashes['sha256']:
                print(Fore.YELLOW + Style.BRIGHT + f'  -> sha256: {hashes["sha256"]}')



            # ----------------- PULSE INFO -----------------

            alv_pulse_info(response_general)

            print(Fore.CYAN + Style.BRIGHT + '\n=== MALWARES ===\n')

            plugins = response_analysis["analysis"]["plugins"]
            itens_printed = 0
            for i in plugins:
        
                if i != "peanomal" and "results" in plugins[i] and plugins[i]["results"] and "detection" in plugins[i]["results"] and plugins[i]["results"]["detection"]:
                    print(Fore.YELLOW + Style.BRIGHT + f'Plugin: {i}')
                    print(f'Detecção: {plugins[i]["results"]["detection"]}\n')
                    itens_printed += 1
            
            if itens_printed == 0:
                print(Fore.MAGENTA + Style.BRIGHT + f'Não foram encontrados dados relevantes relacionados a detecção.')


    except Exception as e:
        print(Fore.RED + Style.BRIGHT + "\n-=-=- ERROR - AlienVault -=-=-")
        print(e)
        print(Fore.RED + Style.BRIGHT + "-=-=- ERROR - AlienVault -=-=-\n")