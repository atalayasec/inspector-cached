import hashlib
from datetime import datetime


def hash_bytes(data):
    """Returns the hexdigest of any bytes-like object received,
    encoding to default encoding if str is found"""
    h = hashlib.sha256()
    if isinstance(data, str):
        data = data.encode()
    h.update(data)
    return h.hexdigest()


def cache_buster(response):
    """Add the cache busting headers to the passed request"""
    response.headers['Last-Modified'] = datetime.now()
    response.headers[
        'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


def score_creator(servicename, score, d):
    """Utility function to build a jsonifiable object to return via the api"""
    ret = {
        "service": servicename,
        "score": score,
    }
    ret.update(d)
    return ret
