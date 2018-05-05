from .common import *
from .util import *

try:
    import requests
except:
    pass
else:

    options["have_https"] = True

    HTTPS_TIMEOUT=5

    def send_request_https(message, url):
        """Send request via HTTPS"""

        headers = {
            'Accept': 'application/dns-udpwireformat',
            'Content-Type' : 'application/dns-udpwireformat',
        }
        resp = requests.post(url, headers=headers, data=message,
                             timeout=HTTPS_TIMEOUT)
        status_code = resp.status_code

        if status_code != 200:
            print("ERROR: HTTP Response Code: {}".format(status_code))
            print(resp.headers)
            return None
        else:
            return resp.content

