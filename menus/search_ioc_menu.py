from colorama import Fore, Back, Style, init
from APIs.virus_total.ip_addresses import vt_get_ip
from APIs.otx_alienvault.ip_addresses import alv_get_ip
from APIs.ibm_xforce.ip_addresses import xfr_get_ip
from APIs.virus_total.url import vt_get_url
from APIs.otx_alienvault.url import alv_get_url
from APIs.ibm_xforce.url import xfr_get_url
from APIs.virus_total.hash import vt_get_hash
from APIs.otx_alienvault.hash import alv_get_hash
from APIs.ibm_xforce.hash import xfr_get_hash
from menus.functions.keys_organizer import keys_organizer
from menus.functions.file_to_hash import file_to_hash
from menus.functions.ip_checker import ip_checker
from menus.functions.url_checker import url_checker
from time import sleep
import os
import multiprocessing as mp


init(autoreset=True)

def search_ioc_menu():
    while True:

        file = open('api_keys.txt', 'r')
        api_names, api_keys = keys_organizer(file)
        hasVirusTotal = bool('virustotal' in api_names)
        hasAlienVault = bool('alienvault' in api_names)
        hasXforce = bool('xforce' in api_names)

        print(Fore.YELLOW + Style.BRIGHT + '\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-')

        print(Fore.CYAN + Style.BRIGHT + '\n=== PESQUISAR INDICADORES DE COMPROMETIMENTO ===\n')
        
        print(Fore.YELLOW + 'Escolha uma opção:')
        print('1 - Análise de arquivo')
        print('2 - Análise de hash')
        print('3 - Análise de IP')
        print('4 - Análise de URL')
        print('0 - Voltar\n')

        try:
            option = int(input('Opção: '))

            if option < 0 or option > 4:
                print(Fore.RED + Style.BRIGHT + '\nOpção inválida, tente novamente.')

            elif option == 0:
                print('\nVoltando...\n')
                break

            elif option == 1:
                file = input('\nCaminho do arquivo: ')
                file = "\\\\".join(file.split('\\'))
                while file == "" or not os.path.isfile(file):
                    print(Fore.RED + Style.BRIGHT + 'Valor inválido. Tente novamente.')
                    sleep(1)
                    file = input('\nCaminho do arquivo: ')
                    file = "\\\\".join(file.split('\\'))

                hash = file_to_hash(file)
                pool = mp.Pool()      
                if hasVirusTotal:
                    res1 = pool.apply_async(vt_get_hash, [api_keys[api_names.index('virustotal')], hash], callback=None)
                if hasAlienVault:
                    res2 = pool.apply_async(alv_get_hash, [api_keys[api_names.index('alienvault')], hash], callback=None)
                if hasXforce:
                    res3 = pool.apply_async(xfr_get_hash, [api_keys[api_names.index('xforce')], hash], callback=None)

                if hasVirusTotal:
                    res1.get()
                    sleep(1)
                if hasAlienVault:
                    res2.get()
                    sleep(1)
                if hasXforce:
                    res3.get()
                    sleep(1)
            
            elif option == 2:
                hash = input('\nDigite a hash: ')
                while hash == "":
                    print(Fore.RED + Style.BRIGHT + 'Valor inválido. Tente novamente.')
                    sleep(1)
                    hash = input('\nDigite a hash: ')

                pool = mp.Pool()      
                if hasVirusTotal:
                    res1 = pool.apply_async(vt_get_hash, [api_keys[api_names.index('virustotal')], hash], callback=None)
                if hasAlienVault:
                    res2 = pool.apply_async(alv_get_hash, [api_keys[api_names.index('alienvault')], hash], callback=None)
                if hasXforce:
                    res3 = pool.apply_async(xfr_get_hash, [api_keys[api_names.index('xforce')], hash], callback=None)

                if hasVirusTotal:
                    res1.get()
                    sleep(1)
                if hasAlienVault:
                    res2.get()
                    sleep(1)
                if hasXforce:
                    res3.get()
                    sleep(1)
            
            elif option == 3:        
                ip_addr = input('\nDigite o IP: ')
                while ip_addr == "" or not ip_checker(ip_addr):
                    print(Fore.RED + Style.BRIGHT + 'Valor inválido. Tente novamente.')
                    sleep(1)
                    ip_addr = input('\nDigite o IP: ')

                pool = mp.Pool()      
                if hasVirusTotal:
                    res1 = pool.apply_async(vt_get_ip, [api_keys[api_names.index('virustotal')], ip_addr], callback=None)
                if hasAlienVault:
                    res2 = pool.apply_async(alv_get_ip, [api_keys[api_names.index('alienvault')], ip_addr], callback=None)
                if hasXforce:
                    res3 = pool.apply_async(xfr_get_ip, [api_keys[api_names.index('xforce')], ip_addr], callback=None)

                if hasVirusTotal:
                    res1.get()
                    sleep(1)
                if hasAlienVault:
                    res2.get()
                    sleep(1)
                if hasXforce:
                    res3.get()
                    sleep(1)

            elif option == 4:
                url = input('\nDigite a URL: ')
                while url == "" or not url_checker(url):
                    print(Fore.RED + Style.BRIGHT + 'Valor inválido. Tente novamente.')
                    sleep(1)
                    url = input('\nDigite a URL: ')

                pool = mp.Pool()      
                if hasVirusTotal:
                    res1 = pool.apply_async(vt_get_url, [api_keys[api_names.index('virustotal')], url], callback=None)
                if hasAlienVault:
                    res2 = pool.apply_async(alv_get_url, [api_keys[api_names.index('alienvault')], url], callback=None)
                if hasXforce:
                    res3 = pool.apply_async(xfr_get_url, [api_keys[api_names.index('xforce')], url], callback=None)

                if hasVirusTotal:
                    res1.get()
                    sleep(1)
                if hasAlienVault:
                    res2.get()
                    sleep(1)
                if hasXforce:
                    res3.get()
                    sleep(1)

        except: 
            print(Fore.RED + Style.BRIGHT + '\nOpção inválida, tente novamente.')
            sleep(1)

