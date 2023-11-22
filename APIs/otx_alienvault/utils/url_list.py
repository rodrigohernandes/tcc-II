from colorama import Fore, Style, init
init(autoreset=True)

def alv_url_list(response):
    if len(response['url_list']) > 0:
        print(Fore.CYAN + Style.BRIGHT + '\n=== LISTA DE URLS ===\n')

        for i in response['url_list'][0:10]:
            print(Fore.YELLOW + Style.BRIGHT + f"-> {i['url']}")
            if 'httpcode' in i:
                print(f"Status Code: {i['httpcode']}\n")

        if len(response['url_list']) > 10:
            print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(response["url_list"]) - 10})')