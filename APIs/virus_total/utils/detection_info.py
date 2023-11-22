from colorama import Fore, Style, init
import itertools
init(autoreset=True)  

def detection_info(attributes, analysis_stats, analysis_results):
    print(Fore.CYAN + Style.BRIGHT + f'\n=== CONTAGEM TOTAL DAS CLASSIFICAÇÕES ===\n')

    reputation = attributes["reputation"]
    reputation = reputation < 0 and Fore.RED + f"{reputation}" or Fore.GREEN + f"{reputation}"
    print(f'Reputação: {reputation}')
    if 'times_submitted' in attributes:
        print(f"Total de vezes enviado para análise: {attributes['times_submitted']}\n")


    for i in analysis_stats:
        print(f'{i}: {analysis_stats[i]}')

    if analysis_stats['malicious'] == 0 and analysis_stats['suspicious'] == 0:
        print(Fore.MAGENTA + '\nNenhum motor de busca identificou este IP como malicioso ou como suspeito\n')

    else:
        print(Fore.CYAN + Style.BRIGHT + f'\n=== DETECÇÃO ===\n')

        malicious_or_suspicious_itens = []

        for i in analysis_results:
            if analysis_results[i]['category'] == 'malicious' or analysis_results[i]['category'] == 'suspicious':
                malicious_or_suspicious_itens.append(analysis_results[i])

        for i in malicious_or_suspicious_itens[0:10]:
            print(Fore.YELLOW + Style.BRIGHT + (i['engine_name']).upper())

            category = i['category']
            if category == 'malicious':
                category = Fore.RED + Style.BRIGHT + f"{category}"
            else:
                category = Fore.YELLOW + Style.BRIGHT + f"{category}"

            print(f"Classificação: {category}")
            print(f"Resultado: {i['result']}")
            print(f"Método: {i['method']}\n")

        if len(malicious_or_suspicious_itens) > 10:
            print(Fore.YELLOW + Style.BRIGHT + f'-> Entre outras ({len(malicious_or_suspicious_itens) - 10})\n')