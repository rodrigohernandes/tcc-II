import re

def url_checker(url):
  
  regex = r"((http|https)://)?(www\.)?" + \
         r"[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*?\.[a-zA-Z]{2,6}" + \
         r"(/[a-zA-Z0-9_-]+)?(\?[a-zA-Z0-9_-]+=[^&]+)?(\#[a-zA-Z0-9_-]+)?"
  match = re.match(regex, url)
  return bool(match)