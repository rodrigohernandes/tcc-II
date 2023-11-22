from colorama import Fore, Style, init
import os
from time import sleep
from menus.search_ioc_menu import search_ioc_menu
from menus.api_config_menu import api_config_menu

init(autoreset=True)

def main():

    while True:
        print(Fore.YELLOW + Style.BRIGHT + '\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-')

        print(Fore.CYAN + Style.BRIGHT + '\n=== O UM PROGRAMA PARA TUDO ANALISAR ===\n')
        
        print(Fore.YELLOW + Style.BRIGHT + 'Escolha uma opção:')
        print('1 - Pesquisar IOCs')
        print('2 - Configurar chaves de API')
        print('0 - Sair\n')

        try:
            option = int(input('Opção: '))

            if option < 0 or option > 2:
                print(Fore.RED + Style.BRIGHT + '\nOpção inválida, tente novamente.')
                sleep(1)

            elif option == 0:
                print('\nSaindo...\n')
                break

            elif option == 1:
                if not os.path.isfile('api_keys.txt'):
                    print(Fore.RED + Style.BRIGHT + '\nOh, não :(\n')
                    print(Fore.RED + Style.BRIGHT + 'Para acessar esta opção, primeiro é necessário configurar as suas chaves de API.\nTente novamente após realizar a configuração!')
                    sleep(2)

                else:
                    api_file = open('api_keys.txt', 'r')
                    api_count = len(api_file.readlines())

                    if api_count == 0:
                        print(Fore.RED + Style.BRIGHT + '\nOh, não :(\n')
                        print(Fore.RED + Style.BRIGHT + 'Um arquivo de chaves de API foi detectado com sucesso! Entrento, não há nenhuma chave registrada nele.\n')
                        print(Fore.RED + Style.BRIGHT + 'Adicione as chaves e tente novamente!\n')
                        sleep(2)

                    elif api_count > 0 and api_count < 3:
                        print(Fore.YELLOW + Style.BRIGHT + '\nAVISO!\n')
                        print(Fore.YELLOW + Style.BRIGHT + 'Um arquivo de chaves de API foi detectado com sucesso! Entrento, há alguma chave de API faltando!\n')
                        print(Fore.YELLOW + Style.BRIGHT + 'Ainda será possível executar o programa, porém a experiência será reduzida ao número de chaves cadastradas.\n')
                        sleep(2)
                        option = input('Deseja continuar? (S/N) ').lower()
                        while option == '' or (option != 's' and option != 'n'):
                            print(Fore.RED + Style.BRIGHT + 'Valor inválido. Tente novamente.')
                            sleep(1)
                            option = input('\nDeseja continuar? (S/N) ')

                        if option == 's':
                            search_ioc_menu()

                        else:
                            print('\nVoltando...\n')
                            sleep(1)

                    else:
                        search_ioc_menu()

            elif option == 2:
                api_config_menu()

        except: 
            print(Fore.RED + Style.BRIGHT + '\nOpção inválida, tente novamente.')
            sleep(1)

    exit()


if __name__ == "__main__":
    main()