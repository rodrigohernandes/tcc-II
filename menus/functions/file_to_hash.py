import hashlib

def file_to_hash(filepath):
    file = open(filepath, 'rb')
    sha256_hash = hashlib.sha256(file.read()).hexdigest()

    return sha256_hash
