from .keys_organizer import keys_organizer
from colorama import Fore, Style

def overwrite_key(file_path, api, key):

    file = open(file_path, 'r+')
    api_names, api_keys = keys_organizer(file)
    file.close()

    file = open(file_path, 'w+')
    api_keys[api_names.index(api)] = key

    for i in range(len(api_names)):
        file.write(f'{api_names[i]}:{api_keys[i]}\n')

    file.close()

    print(Fore.GREEN + Style.BRIGHT + '\nChave adicionada com sucesso!\n')
