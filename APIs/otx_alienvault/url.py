import requests, re
from colorama import Fore, Style, init
from .utils.pulse_info import alv_pulse_info
from .utils.url_list import alv_url_list
from time import sleep
init(autoreset=True)

def alv_get_url(api, str):

    isUrl = re.search("^http", str)
    isDomain = len(re.findall('\.', str)) == 1

    try:

        if isUrl:
            response_general = requests.get(f'https://otx.alienvault.com/api/v1/indicator/url/{str}/general', 
            headers={
                'X-OTX-API-KEY': api
            }).json()

            response_url_list = requests.get(f'https://otx.alienvault.com/api/v1/indicator/url/{str}/url_list', 
            headers={
                'X-OTX-API-KEY': api
            }).json()

            if "detail" in response_general and "endpoint not found" in response_general['detail']:
                
                newUrl = re.split("\?|#", str)[0]
                response_submit_url = requests.post(f'https://otx.alienvault.com/api/v1/indicators/submit_url',
                data = {
                    "url": newUrl,
                },
                headers={
                    'X-OTX-API-KEY': api
                })

                response_submitted_urls = requests.get(f'https://otx.alienvault.com/api/v1/indicators/submitted_urls', 
                headers={
                    'X-OTX-API-KEY': api
                }).json() 

                isComplete = response_submitted_urls["results"][0]["complete_date"]

                while not isComplete:
                    sleep(5)
                    response_submitted_urls = requests.get(f'https://otx.alienvault.com/api/v1/indicators/submitted_urls', 
                    headers={
                        'X-OTX-API-KEY': api
                    }).json() 

                    isComplete = response_submitted_urls["results"][0]["complete_date"]

                alv_get_url(api, newUrl)

            else:
                print(Fore.MAGENTA + Style.BRIGHT + '\n-=-=-=- OTX Alien Vault -=-=-=-\n')
                print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')
                
                if "country_name" in response_url_list:
                    print(f'País: {response_url_list["country_name"]}')
                if "continent_code" in response_url_list:
                    print(f'Continente: {response_url_list["continent_code"]}\n')

                print(f'Tipo do indicador: {response_general["type"]}') 
                print(f'Domínio: {response_general["domain"]}')
                print(f'Hostname: {response_general["hostname"]}')
                print(f'WHOIS Lookup: {response_general["whois"]}')


                if response_general['validation']:
                    for i in response_general['validation']:
                        if i['source'] == 'whitelist':
                            print('Veredito: ' + Fore.GREEN + f"{i['name']}")


                # ----------------- URL LIST -----------------
                alv_url_list(response_url_list)


                # ----------------- PULSE INFO -----------------
                alv_pulse_info(response_general)


        elif isDomain:
            print(Fore.MAGENTA + Style.BRIGHT + '\n-=-=-=- OTX Alien Vault -=-=-=-\n')

            response_general = requests.get(f'https://otx.alienvault.com/api/v1/indicator/domain/{str}/general', 
            headers={
                'X-OTX-API-KEY': api
            }).json()

            response_url_list = requests.get(f'https://otx.alienvault.com/api/v1/indicator/domain/{str}/url_list', 
            headers={
                'X-OTX-API-KEY': api
            }).json()

            response_malware = requests.get(f'https://otx.alienvault.com/api/v1/indicator/domain/{str}/malware', 
            headers={
                'X-OTX-API-KEY': api
            }).json()

            response_geo = requests.get(f'https://otx.alienvault.com/api/v1/indicator/domain/{str}/geo', 
            headers={
                'X-OTX-API-KEY': api
            }).json()

            print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')
            
            if response_geo:
                print(f'País: {response_geo["country_name"]}')
                print(f'Continente: {response_geo["continent_code"]}\n')

            print(f'Tipo do indicador: {response_general["type"]}')
            print(f'WHOIS Lookup: {response_general["whois"]}')


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

        else:
            print(Fore.MAGENTA + Style.BRIGHT + '\n-=-=-=- OTX Alien Vault -=-=-=-\n')

            response_general = requests.get(f'https://otx.alienvault.com/api/v1/indicator/hostname/{str}/general', 
            headers={
                'X-OTX-API-KEY': api
            }).json()

            response_url_list = requests.get(f'https://otx.alienvault.com/api/v1/indicator/hostname/{str}/url_list', 
            headers={
                'X-OTX-API-KEY': api
            }).json()

            response_malware = requests.get(f'https://otx.alienvault.com/api/v1/indicator/hostname/{str}/malware', 
            headers={
                'X-OTX-API-KEY': api
            }).json()

            response_geo = requests.get(f'https://otx.alienvault.com/api/v1/indicator/hostname/{str}/geo', 
            headers={
                'X-OTX-API-KEY': api
            }).json()

            print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')
            
            if response_geo:
                print(f'País: {response_geo["country_name"]}')
                print(f'Continente: {response_geo["continent_code"]}\n')

            print(f'Tipo do indicador: {response_general["type"]}')
            print(f'Domínio: {response_general["domain"]}')
            print(f'WHOIS Lookup: {response_general["whois"]}')


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