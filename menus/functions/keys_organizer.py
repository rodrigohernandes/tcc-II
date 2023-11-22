def keys_organizer(file):
    
    keys = file.readlines()
    api_name = []
    api_key = []

    for i in range(len(keys)):
        api_name.append(keys[i].split(':')[0])
        api_key.append(keys[i].split(':')[1].split('\n')[0])

    file.close()

    return api_name, api_key