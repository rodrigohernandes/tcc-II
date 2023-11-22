import requests
from .utils.malware import malware_info
from colorama import Fore, Style, init
init(autoreset=True)

def xfr_get_hash(api, hash):

    response = requests.get(f"https://api.xforce.ibmcloud.com/api/malware/{hash}", headers= {
        "Authorization": f"Basic {api}",
        "accept": "application/json"
    })

    try:

        print(Fore.MAGENTA + Style.BRIGHT + '\n-=-=-=- X-FORCE -=-=-=-\n')

        if response.status_code != 200:
            print(Fore.RED + Style.BRIGHT + "Nenhum dado encontrado sobre o arquivo/hash informado\n")

        else:

            response = response.json()
            malware = response['malware']
            origins = malware['origins']
            risco = malware['risk'].upper()
            risco = risco == 'LOW' and Fore.GREEN + f"{risco}" or (risco == 'MEDIUM' and Fore.YELLOW + f"{risco}" or Fore.RED + f"{risco}")
            tags = response['tags']

            print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')  

            print(f'Tipo do arquivo: {malware["type"].upper()}')
            print(f'Risco: {risco}')

            if tags:
                print("Tags:")
                for i in tags[0:10]:
                    print(Fore.YELLOW + Style.BRIGHT + f"  -> {i['tag']}")
                
                if len(tags) > 10:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(tags) - 10})')

            print(Fore.CYAN + Style.BRIGHT + '\n=== MALWARES ===\n')  

            for i in origins:
                print(f'Origem: {Fore.YELLOW + Style.BRIGHT + i}')
                fonte = origins[i] 
                if i == 'external':

                    print(f'Fonte da detecção: {fonte["source"]}')
                    print(f'Visto pela primeira vez: {fonte["firstSeen"]}')
                    print(f'Visto pela última vez: {fonte["lastSeen"]}')
                    if fonte["family"]:
                        print(f'Família do malware: {", ".join(fonte["family"])}')
                    if "malwareType" in fonte:
                        print(f'Tipo do malware: {fonte["malwareType"]}')
                    if fonte["detectionCoverage"]:
                        print(f'Cobertura da comunidade: {fonte["detectionCoverage"]}%')
                    if "platform" in fonte:
                        print(f'Plataforma: {fonte["platform"]}')
                    if "subPlatform" in fonte:
                        print(f'Sub-plataforma: {fonte["subPlatform"]}')

                elif i != 'external' and not i == 'subjects':
                    
                    malware_info(origins[i])

    except Exception as e:
        print(Fore.RED + Style.BRIGHT + "-=-=- ERROR - X-Force -=-=-")
        print(e)
        print(Fore.RED + Style.BRIGHT + "-=-=- ERROR - X-Force -=-=-")