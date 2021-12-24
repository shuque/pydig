"""
DNS over HTTPS.

"""

from .common import options
import requests

HTTPS_TIMEOUT = 5

def checkContentLength(r):
    """
    requests library doesn't check content length!
    https://blog.petrzemek.net/2018/04/22/on-incomplete-http-reads-and-the-requests-library-in-python/
    """
    expected = r.headers.get('Content-Length')
    if expected is not None:
        actual = r.raw.tell()
        expected = int(expected)
        if actual < expected:
            raise IOError(
                'incomplete read ({} bytes read, {} more expected)'.format(
                    actual, expected - actual)
            )
        return


def send_request_https(message, url):
    """Send request via HTTPS"""

    headers = {
        'Accept': 'application/dns-message',
        'Content-Type' : 'application/dns-message',
    }
    resp = requests.post(url, headers=headers, data=message,
                         timeout=HTTPS_TIMEOUT)
    checkContentLength(resp)
    status_code = resp.status_code
    if status_code != 200:
        print("ERROR: HTTP Response Code: {}".format(status_code))
        print(resp.headers)
        if resp.text:
            print(resp.text)
        return None
    else:
        return resp.content
