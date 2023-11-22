import requests
from .utils.malware import malware_info
from colorama import Fore, Style, init
init(autoreset=True)

def xfr_get_url(api, url):

    response = requests.get(f"https://api.xforce.ibmcloud.com/api/url/{url}", headers= {
        "Authorization": f"Basic {api}",
        "accept": "application/json"
    })

    response_history = requests.get(f"https://api.xforce.ibmcloud.com/api/url/history/{url}", headers= {
        "Authorization": f"Basic {api}",
        "accept": "application/json"
    })

    response_malware = requests.get(f"https://api.xforce.ibmcloud.com/api/url/malware/{url}", headers= {
        "Authorization": f"Basic {api}",
        "accept": "application/json"
    })

    try:
        
        print(Fore.MAGENTA + Style.BRIGHT + '\n-=-=-=- X-FORCE -=-=-=-\n')

        if response.status_code != 200:
            print(Fore.RED + Style.BRIGHT + "Nenhum dado encontrado sobre informações gerais da URL informada\n")
        
        else:

            response = response.json()

            print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')

            print(f'URL: {response["result"]["url"]}')
            if response['result']['score'] is not None:
                risco = response["result"]["score"]
                risco = risco < 4 and Fore.GREEN + f"{risco}" or (risco < 7 and Fore.YELLOW + f"{risco}" or Fore.RED + f"{risco}")
                print(Style.BRIGHT + f'Risco: {risco}\n')
            
            else:
                print(Fore.MAGENTA + Style.BRIGHT + f'Risco: desconhecido\n')

            if "application" in response["result"]:
                application = response["result"]["application"]
                print(f'Nome: {application["name"]}')
                print(f'Descrição: {application["description"]}')
                if 'baseurl' in application:
                    print(f'URL base: {application["baseurl"]}')
                risco = application["score"]
                risco = risco < 4 and Fore.GREEN + f"{risco}" or (risco < 7 and Fore.YELLOW + f"{risco}" or Fore.RED + f"{risco}")
                print(f'Risco: {risco}\n')

                if "actions" in application:
                    print('Ações:')
                    for i in application["actions"]:
                        print(Fore.YELLOW + Style.BRIGHT + f'  -> {i}')

                if "riskfactors" in application:
                    print('\nFatores de risco:')
                    fatores = application["riskfactors"]
                    for i in fatores:
                        print(Fore.YELLOW + Style.BRIGHT + f'  -> {i}')
                        print(f'     Descrição: {fatores[i]["description"]}')
                        print(f'     Valor: {fatores[i]["value"]}\n')
                
            tags = response["tags"]
            if tags:
                print("Tags:")
                for i in tags[0:10]:
                    print(Fore.YELLOW + Style.BRIGHT + f"  -> {i['tag']}")
                
                if len(tags) > 10:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(tags) - 10})')

        if response_history.status_code != 200:

            print(Fore.RED + Style.BRIGHT + "Nenhum dado encontrado sobre histórico da URL informada\n")
        
        else:

            response_history = response_history.json()
            historico = response_history["history"]
            if historico:
                print(Fore.CYAN + Style.BRIGHT + '\n=== HISTÓRICO ===\n')

                has_score = True
                for i in historico:
                    if "score" not in i:
                        has_score = False
                if has_score:
                    historico.sort(key=lambda dict: dict["score"], reverse=True)
                
                for i in historico[0:10]:
                    dia, hora = i["created"].split('T')
                    dia = '-'.join(list(reversed(dia.split('-'))))
                    hora = hora.split('.')[0]
                    print(Fore.YELLOW + Style.BRIGHT + f'Data da detecção: {dia}, às {hora}')

                    if i["cats"]:
                        print('Categorias:')
                        for j in i["cats"]:
                            print(Fore.YELLOW + Style.BRIGHT + f'  -> {j}')
                            print(f'       Confiança: {i["cats"][j]["confidence"]}')
                            print(f'       Descrição: {i["cats"][j]["description"]}')
                            print(f'       Motivo: {i["cats"][j]["reasons"][0]["description"]}\n')
                        
                    if "score" in i:
                        risco = i["score"]
                        risco = risco < 4 and Fore.GREEN + f"{risco}" or (risco < 7 and Fore.YELLOW + f"{risco}" or Fore.RED + f"{risco}")
                        print(Style.BRIGHT + f'       Risco: {risco}\n')

                if len(historico) > 10:
                    print(Fore.YELLOW + Style.BRIGHT + f'-> Entre outras ({len(historico) - 10})')

        if response_malware.status_code != 200:

            print(Fore.RED + Style.BRIGHT + "\nNenhum dado encontrado sobre malwares da URL informada\n")
        
        else:

            response_malware = response_malware.json()
            malwares = response_malware["malware"]
            if malwares:
                print(Fore.CYAN + Style.BRIGHT + '\n=== MALWARES ===\n')

                malware_info(malwares)

    except Exception as e:
        print(Fore.RED + Style.BRIGHT + "-=-=- ERROR - X-Force -=-=-")
        print(e)
        print(Fore.RED + Style.BRIGHT + "-=-=- ERROR - X-Force -=-=-")