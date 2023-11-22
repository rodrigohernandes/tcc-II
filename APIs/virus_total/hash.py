import requests
from colorama import Fore, Style, init
from .utils.detection_info import detection_info
init(autoreset=True)

def vt_get_hash(api, hash):

    response = requests.get(f'https://www.virustotal.com/api/v3/files/{hash}', 
        headers={
            'x-apikey': api,
            'accept': 'application/json'
        })
    
    
    try: 
        print(Fore.MAGENTA + Style.BRIGHT + '\n-=-=-=- VirusTotal -=-=-=-\n')

        if response.status_code != 200:
            print(Fore.RED + Style.BRIGHT + 'Nenhum dado encontrado sobre o arquivo/hash informado\n')

        else:
            response = response.json()
            attributes = response['data']['attributes']
            analysis_stats = response['data']['attributes']['last_analysis_stats']
            analysis_results = response['data']['attributes']['last_analysis_results']

            print(Fore.CYAN + Style.BRIGHT + '\n=== INFORMAÇÕES GERAIS ===\n')

            if 'meaningful_name' in attributes:
                print(f"Nome do arquivo: {attributes['meaningful_name']}")
            if 'names' in attributes and len(attributes['names']) > 0:
                print(f"Possíveis nomes:")
                for i in attributes['names']:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> {i}')

            print(f"\nTipo de arquivo: {response['data']['type']}")
            if 'type_extension' in attributes:
                print(f"Extensão do arquivo: {attributes['type_extension']}")
            print(f"Descrição do tipo de arquivo: {attributes['type_description']}")
            if 'type_tags' in attributes:
                print("Tags do tipo de arquivo:")
                for i in attributes['type_tags']:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> {i}')
            
            if 'tags' in attributes:
                print("\nTags:")
                for i in attributes['tags'][0:10]:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> {i}')

                if len(attributes['tags']) > 10:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(attributes["tags"]) - 10})')


            print(Fore.CYAN + Style.BRIGHT + '\n=== ANÁLISE DO ARQUIVO ===\n')
            
            if 'signature_info' in attributes:
                info_assinatura = attributes["signature_info"]
                print('Informações da assinatura do arquivo:')
                if "product" in info_assinatura:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Produto: {info_assinatura["product"]}')
                if "internal name" in info_assinatura:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Nome interno: {info_assinatura["internal name"]}')
                if "copyright" in info_assinatura:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Copyright: {info_assinatura["copyright"]}')
                if "original name" in info_assinatura:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Nome original: {info_assinatura["original name"]}')
                if "file version" in info_assinatura:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Versão do arquivo: {info_assinatura["file version"]}')
                if "description" in info_assinatura:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Descrição: {info_assinatura["description"]}')
            
            if 'detectiteasy' in attributes:
                print('\nAnálise pelo utilitário "detectiteasy":')
                print(f'  Tipo do arquivo: {attributes["detectiteasy"]["filetype"]}')
                print(f'  Valores:')
                valores = attributes["detectiteasy"]["values"]
                for i in range(len(valores[0:10])):
                    if 'info' in valores:
                        print( Fore.YELLOW + Style.BRIGHT + f'    -> Informação: {valores[i]["info"]}')

                    if 'version' in valores:
                        print(Fore.YELLOW + Style.BRIGHT + f'    -> Versão: {valores[i]["version"]}')

                    if 'type' in valores:
                        print(Fore.YELLOW + Style.BRIGHT + f'    -> Tipo: {valores[i]["type"]}')

                    if 'name' in valores:
                        print(Fore.YELLOW + Style.BRIGHT + f'    -> Nome: {valores[i]["name"]}')
                if len(valores) > 10:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(valores) - 10})')


            if 'known_distributors' in attributes:
                print('\nDistribuidores conhhecidos:')
                for i in attributes['known_distributors']['distributors'][0:10]:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> {i}')
                if len(attributes['known_distributors']['distributors']) > 10:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(attributes["known_distributors"]["distributors"]) - 10})')


            if 'trid' in attributes:
                print('\nAnálise TrID')
                for i in attributes['trid'][0:10]:
                    print(Fore.YELLOW + Style.BRIGHT + f"  -> Tipo do arquivo: {i['file_type']}")
                    print(f"    - Probabilidade: {i['probability']}%\n")
                if len(attributes['trid']) > 10:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(attributes["trid"]) - 10})')

            if 'magic' in attributes:
                print(f'\nAnálise do bit mágico: {attributes["magic"]}')

            print(Fore.CYAN + Style.BRIGHT + '\n=== HASHES ===\n')

            print(f'SHA256: {attributes["sha256"]}')
            print(f'SHA1: {attributes["sha1"]}')
            print(f'MD5: {attributes["md5"]}')
            if 'imphash' in attributes:
                print(f'IMPHASH: {attributes["imphash"]}')


            # ------------------- DETECÇÕES -------------------
            detection_info(attributes, analysis_stats, analysis_results)


            if 'popular_threat_classification' in attributes:
                ameaca_popular = attributes['popular_threat_classification']
                print('Classificação de ameaça popular:')
                print(f'  -> Sugestão de rótulo de ameaça: {ameaca_popular["suggested_threat_label"]}')

                print('  -> Categoria popular da ameaça:')
                for i in ameaca_popular['popular_threat_category'][0:10]:
                    print(Fore.YELLOW + Style.BRIGHT + f'    - Categoria: {i["value"]}')
                    print(f'    - Contagem: {i["count"]}\n')
                if len(ameaca_popular['popular_threat_category']) > 10:
                    print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(ameaca_popular["popular_threat_category"]) - 10})')

                if "popular_threat_name" in ameaca_popular:
                    print('  -> Nome popular da ameaça')
                    for i in ameaca_popular['popular_threat_name'][0:10]:
                        print(Fore.YELLOW + Style.BRIGHT + f'    - Nome: {i["value"]}')
                        print(f'    - Contagem: {i["count"]}\n')
                    if len(ameaca_popular['popular_threat_name']) > 10:
                        print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(ameaca_popular["popular_threat_name"]) - 10})')

            if 'sandbox_verdicts' in attributes:
                print(Fore.CYAN + Style.BRIGHT + f'\n=== ANÁLISE DE SANDBOX ===\n')

                sandbox = attributes['sandbox_verdicts']
                for i in sandbox:
                    print(Fore.YELLOW + Style.BRIGHT + f'{i}')
                    if 'category' in sandbox[i]:
                        print(f'Categoria: {sandbox[i]["category"]}')
                    if 'confidence' in sandbox[i]:
                        print(f'Confiança: {sandbox[i]["confidence"]}')
                    if 'malware_classification' in sandbox[i]:
                        print('Classificação do malware:')
                        for j in sandbox[i]['malware_classification']:
                            print(f'  -> {j}')

                    if 'malware_names' in i:
                        print('Nome dos malwares:')
                        for j in sandbox[i]['malware_names']:
                            print(f'  -> {j}')
                
                    print('\n')

    except Exception as e:
        print(Fore.RED + Style.BRIGHT + "-=-=- ERROR - VirusTotal -=-=-")
        print(e)
        print(Fore.RED + Style.BRIGHT + "-=-=- ERROR - VirusTotal -=-=-")