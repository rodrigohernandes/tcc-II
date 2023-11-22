import requests
from colorama import Fore, Style, init
from .utils.malware import malware_info
init(autoreset=True)

def xfr_get_ip(api, ip):

    response = requests.get(f"https://api.xforce.ibmcloud.com/api/ipr/{ip}", headers= {
        "Authorization": f"Basic {api}",
        "accept": "application/json"
    })

    response_malware = requests.get(f"https://api.xforce.ibmcloud.com/api/ipr/malware/{ip}", headers= {
        "Authorization": f"Basic {api}",
        "accept": "application/json"
    })

    try:

        print(Fore.MAGENTA + Style.BRIGHT + '\n-=-=-=- X-FORCE -=-=-=-\n')

        if response.status_code != 200:
            print(Fore.RED + Style.BRIGHT + "Nenhum dado encontrado sobre informações gerais do IP informado\n")
            
        else:
            response = response.json()

            print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')

            print(f'País: {response["geo"]["country"]}\n')

            print('Sub-redes:')
            subnets = response['subnets']
            for i in subnets:
                print(Fore.YELLOW + Style.BRIGHT + f'  -> {i["subnet"]}')
                if "geo" in i:
                    print(f'     País: {i["geo"]["country"]}')
                if "asns" in i:
                    for j in i["asns"].keys():
                        print(f'     ASN: {j}')
                        if "Company" in i["asns"][j]:
                            print(f'     Companhia: {i["asns"][j]["Company"]}')


                risco = i["score"]
                risco = risco < 4 and Fore.GREEN + f"{risco}" or (risco < 7 and Fore.YELLOW + f"{risco}" or Fore.RED + f"{risco}")
                print(Style.BRIGHT + f'     Risco: {risco}\n')
            
            risco = response["score"]
            risco = risco < 4 and Fore.GREEN + f"{risco}" or (risco < 7 and Fore.YELLOW + f"{risco}" or Fore.RED + f"{risco}")
            print(f'Risco do IP: {risco}')
            print(f'Motivo: {response["reason"]}\n')

            tags = response["tags"]
            if tags:
                print("Tags:")
                for i in tags[0:10]:
                    print(Fore.YELLOW + Style.BRIGHT + f"  -> {i['tag']}")
                
                if len(tags) > 10:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(tags) - 10})')


            print(Fore.CYAN + Style.BRIGHT + '\n=== HISTÓRICO DE DETECÇÕES ===\n')

            historico = response["history"]
            historico.sort(key=lambda dict: dict["score"], reverse=True)

            
            for i in historico[0:10]:
                dia, hora = i["created"].split('T')
                dia = '-'.join(list(reversed(dia.split('-'))))
                hora = hora.split('.')[0]
                print(Fore.YELLOW + Style.BRIGHT + f'Data da detecção: {dia}, às {hora}')

                if "malware_extended" in i:
                    malware, *resto = i['malware_extended'].keys()
                    print(Fore.RED + Style.BRIGHT + f'{malware}: {i["malware_extended"][malware]}')

                risco = i["score"]
                risco = risco < 4 and Fore.GREEN + f"{risco}" or (risco < 7 and Fore.YELLOW + f"{risco}" or Fore.RED + f"{risco}")
                print(Style.BRIGHT + f'Risco: {risco}')
                print(f'Motivo: {i["reason"]}\n')

            if len(historico) > 10:
                print(Fore.YELLOW + Style.BRIGHT + f'-> Entre outras ({len(historico) - 10})')


        if response_malware.status_code != 200:
            print(Fore.RED + Style.BRIGHT + "Nenhum dado encontrado sobre malwares do IP informado\n")

        else:
            response_malware = response_malware.json()
            malware = response_malware['malware']
            if malware:
                print(Fore.CYAN + Style.BRIGHT + '\n=== MALWARES ===\n')
                
                print('Quantidade total de detecções: ' + Fore.RED + Style.BRIGHT + f'{len(malware)}\n')
                malware_info(malware)


    except Exception as e:
        print(Fore.RED + Style.BRIGHT + "-=-=- ERROR - X-Force -=-=-")
        print(e)
        print(Fore.RED + Style.BRIGHT + "-=-=- ERROR - X-Force -=-=-")