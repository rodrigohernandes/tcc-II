from time import sleep
import requests
from colorama import Fore, Style, init
from .utils.detection_info import detection_info
init(autoreset=True)

def vt_get_url(api, url):       

    response = requests.post('https://www.virustotal.com/api/v3/urls',
    data=f'url={url}', 
    headers={
        "accept": "application/json",
        'x-apikey': api,
        "content-type": "application/x-www-form-urlencoded"
    }).json()
    
    url_id = response['data']['id']

    response = requests.get(f'https://www.virustotal.com/api/v3/analyses/{url_id}', 
        headers={
            'x-apikey': api,
            "accept": "application/json"
        }).json()

    url_id = response['meta']['url_info']['id']

    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', 
        headers={
            'x-apikey': api,
            "accept": "application/json"
        }).json()

    try:

        if 'data' not in response:
            sleep(5)
            vt_get_url(api, url)

        attributes = response['data']['attributes']
        analysis_stats = response['data']['attributes']['last_analysis_stats']
        analysis_results = response['data']['attributes']['last_analysis_results']

        if len(analysis_results) == 0 or not attributes or not analysis_stats: 
            sleep(5)
            vt_get_url(api, url)

        else:
            print(Fore.MAGENTA + Style.BRIGHT + '\n-=-=-=- VirusTotal -=-=-=-\n')
            print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')

            reputation = attributes["reputation"]
            if reputation < 0:
                reputation = Fore.RED + f"{reputation}"
            else:
                reputation = Fore.GREEN + f"{reputation}"

            print(f'Reputação: {reputation}\n')
            if "title" in attributes:
                print(f'Título: {attributes["title"]}\n')   
            else:
                print(f'Título: Não disponível\n')   

            print(f'URL final: {attributes["last_final_url"]}')
            if "last_http_response_code" in attributes:
                print(f'Última resposta de código HTTP: {attributes["last_http_response_code"]}\n')
                
            print(f'ID SHA256: {response["data"]["id"]}')

            print(Fore.CYAN + Style.BRIGHT + '\n=== CATEGORIAS ===\n')
            for i in attributes['categories']:
                print(Fore.YELLOW + i)
                print(f"{attributes['categories'][i]}\n")

            if attributes["tags"]:
                print(Fore.CYAN + Style.BRIGHT + '\n=== TAGS ===\n')

                for i in attributes['tags'][0:10]:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> {i}')

                if len(attributes['tags']) > 10:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(attributes["tags"]) - 10})')

            # ------------------- DETECÇÕES -------------------
            detection_info(attributes, analysis_stats, analysis_results)

            if 'threat_names' in attributes and len(attributes['threat_names']) > 0:
                print(Fore.CYAN + Style.BRIGHT + '\n=== NOME DAS AMEAÇAS ===\n')
                for i in attributes['threat_names'][0:10]:
                    print(f'-> {i}') 
                if len(attributes['threat_names']) > 10:
                    print(Fore.YELLOW + Style.BRIGHT + f'-> Entre outras ({len(attributes["threat_names"]) - 10})')

            
            if "redirection_chain" in attributes:
                print(Fore.CYAN + Style.BRIGHT + f'\n=== CADEIA DE REDIRECIONAMENTOS ===\n')
                for i in range(len(attributes["redirection_chain"][0:10])):
                    print(f'{i + 1} -> {attributes["redirection_chain"][i]}')
                if len(attributes['redirection_chain']) > 10:
                    print(Fore.YELLOW + Style.BRIGHT + f'-> Entre outras ({len(attributes["redirection_chain"]) - 10})')

            if "outgoing_links" in attributes:
                print(Fore.CYAN + Style.BRIGHT + f'\n=== OUTGOING LINKS ===\n')
                for i in range(len(attributes["outgoing_links"][0:10])):
                    print(f'{i + 1} -> {attributes["outgoing_links"][i]}')
                if len(attributes['outgoing_links']) > 10:
                    print(Fore.YELLOW + Style.BRIGHT + f'-> Entre outras ({len(attributes["outgoing_links"]) - 10})')
              
    except Exception as e:
        
        if e.args[0] != 'data':    
            print(Fore.RED + Style.BRIGHT + "-=-=- ERROR - VirusTotal -=-=-")
            print(e)
            print(Fore.RED + Style.BRIGHT + "-=-=- ERROR - VirusTotal -=-=-")