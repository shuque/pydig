"""
Get default windows resolver.

"""

import subprocess
import re

def get_windows_default_dns():
    """Get windows default resolver"""
    output = subprocess.Popen(["netsh", "interface", "ipv4", "show", "dns"],
                              stdout=subprocess.PIPE).communicate()[0]
    re_ipv4 = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.MULTILINE)
    match_obj = re_ipv4.search(output)
    if match_obj:
        return match_obj.group(0)
    return None
