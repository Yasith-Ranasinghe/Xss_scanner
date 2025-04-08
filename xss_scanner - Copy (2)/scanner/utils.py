import requests

def apply_evasion(payload, technique):
    if technique == 'url_encode':
        return requests.utils.quote(payload)
    elif technique == 'html_entities':
        return ''.join(f'&#{ord(c)};' for c in payload)
    elif technique == 'unicode_escape':
        return payload.encode('unicode-escape').decode()
    return payload