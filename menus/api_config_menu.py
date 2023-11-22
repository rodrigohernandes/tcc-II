from colorama import Fore, Style
import os
from time import sleep
from .functions.keys_organizer import keys_organizer
from .functions.overwrite_key import overwrite_key
import base64

def api_config_menu():

    if os.path.isfile('api_keys.txt'):
        print(Fore.GREEN + Style.BRIGHT + '\nArquivo de chaves detectado com sucesso!')
        file = open('api_keys.txt', 'r')
        api_names, api_keys = keys_organizer(file)
        file.close()
        sleep(1)

    else:
        print(Fore.MAGENTA + Style.BRIGHT + '\nArquivo de chaves não encontrado.\nCriando arquivo...')
        file = open('api_keys.txt', 'a+')
        api_names = []
        file.close()
        sleep(1)

    while True:

        print(Fore.YELLOW + Style.BRIGHT + '\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-')

        print(Fore.CYAN + Style.BRIGHT + '\n=== CONFIGURAÇÃO DE CHAVES DE API ===\n')
        
        print(Fore.YELLOW + 'Escolha uma opção:')
        print('1 - Chave para VirusTotal')
        print('2 - Chave para OTX Alien Vault')
        print('3 - Chave para IBM X-Force')
        print('9 - Arquivo de chaves')
        print('0 - Voltar\n')

        try:

            option = int(input('Opção: '))
            if option != 0 and option != 1 and option != 2 and option != 3 and option != 9:
                print(Fore.RED + Style.BRIGHT + '\nOpção inválida, tente novamente.')

            elif option == 0:
                print('\nVoltando...\n')
                sleep(1)
                break

            else:
            
                if option == 1:

                    if 'virustotal' in api_names:
                        print('\nJá existe um registro para a chave do Virus Total.')
                        option = input('Deseja substituir? (S/N)').lower()
                        while (option != 'n' and option != 's') or option == '' :
                            print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                            sleep(1)
                            option = input('\nDeseja substituir? (S/N) ')

                        if option == 's':
                            api_value = input('\nQual o valor da sua chave de API do Virus Total? ')
                            while api_value == '':
                                print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                                sleep(1)
                                api_value = input('\nQual o valor da sua chave de API do Virus Total? ')
                            overwrite_key('api_keys.txt', 'virustotal', api_value)
                            sleep(1)

                    else:
                        api_value = input('\nQual o valor da sua chave de API do Virus Total? ')
                        while api_value == '':
                            print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                            sleep(1)
                            api_value = input('\nQual o valor da sua chave de API do Virus Total? ')
                        
                        file = open('api_keys.txt', 'a+')
                        file.write(f'virustotal:{api_value}\n')
                        file.close()
                        print(Fore.GREEN + Style.BRIGHT + '\nChave adicionada com sucesso!\n')

                elif option == 2:

                    if 'alienvault' in api_names:
                        print('\nJá existe um registro para a chave do OTX Alien Vault.')
                        option = input('Deseja substituir? (S/N)').lower()
                        while (option != 'n' and option != 's') or option == '' :
                            print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                            sleep(1)
                            option = input('\nDeseja substituir? (S/N) ')

                        if option == 's':
                            api_value = input('\nQual o valor da sua chave de API do OTX Alien Vault? ')
                            while api_value == '':
                                print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                                sleep(1)
                                api_value = input('\nQual o valor da sua chave de API do OTX Alien Vault? ')
                            overwrite_key('api_keys.txt', 'alienvault', api_value)

                    else:
                        api_value = input('\nQual o valor da sua chave de API do OTX Alien Vault? ')
                        while api_value == '':
                            print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                            sleep(1)
                            api_value = input('\nQual o valor da sua chave de API do OTX Alien Vault? ')
                        
                        file = open('api_keys.txt', 'a+')
                        file.write(f'alienvault:{api_value}\n')
                        file.close()
                        print(Fore.GREEN + Style.BRIGHT + '\nChave adicionada com sucesso!\n')
                        sleep(1)

                elif option == 3:

                    if 'xforce' in api_names:
                        print('\nJá existe um registro para a chave do IBM X-Force.')
                        option = input('Deseja substituir? (S/N)').lower()
                        while (option != 'n' and option != 's') or option == '' :
                            print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                            sleep(1)
                            option = input('\nDeseja substituir? (S/N) ')

                        if option == 's':
                            api_key = input('\nQual o valor da sua chave de API do IBM X-Force? ')
                            while api_key == '':
                                print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                                sleep(1)
                                api_key = input('\nQual o valor da sua chave de API do IBM X-Force? ')

                            api_password = input('\nQual o valor da senha da sua chave de API do IBM X-Force? ')
                            while api_password == '':
                                print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                                sleep(1)
                                api_password = input('\nQual o valor da senha da sua chave de API do IBM X-Force? ')
                            
                            data_string = (f"{api_key}:{api_password}")
                            data_bytes = data_string.encode("utf-8")
                            token = base64.b64encode(data_bytes)
                            token = f"{token}".split("'")[1]
                            overwrite_key('api_keys.txt', 'xforce', token)

                    else:
                        api_key = input('\nQual o valor da sua chave de API do IBM X-Force? ')
                        while api_key == '':
                            print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                            sleep(1)
                            api_key = input('\nQual o valor da sua chave de API do IBM X-Force? ')

                        api_password = input('\nQual o valor da senha da sua chave de API do IBM X-Force? ')
                        while api_password == '':
                            print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                            sleep(1)
                            api_password = input('\nQual o valor da senha da sua chave de API do IBM X-Force? ')
                        
                        data_string = (f"{api_key}:{api_password}")
                        data_bytes = data_string.encode("utf-8")
                        token = base64.b64encode(data_bytes)
                        token = f"{token}".split("'")[1]

                        file = open('api_keys.txt', 'a+')
                        file.write(f'xforce:{token}\n')
                        file.close()
                        print(Fore.GREEN + Style.BRIGHT + '\nChave adicionada com sucesso!\n')
                        sleep(1)

                elif option == 9:
                    if api_names:
                        file = open('api_keys.txt', 'r')
                        lines = file.readlines()
                        for line in lines:
                            print(line)
                        file.close()
                        sleep(1)

                    else:
                        print('O arquivo ainda não contem nenhuma informação.')
                        sleep(1)

        except Exception as e:
            print(Fore.RED + Style.BRIGHT + "-=-=- ERROR -=-=-")
            print(e)
            print(Fore.RED + Style.BRIGHT + "-=-=- ERROR -=-=-")

        # except: 
        #     print(Fore.RED + Style.BRIGHT + '\nOpção inválida, tente novamente.')
        #     sleep(1)
