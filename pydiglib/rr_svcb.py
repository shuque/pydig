"""
SVCB and HTTPS RR Types class.

"""

import socket
import struct

from .name import name_from_wire_message


# SVCB (Service Binding RR) Parameter Types
SVCB_PARAM = {
    0: "mandatory",
    1: "alpn",
    2: "no-default-alpn",
    3: "port",
    4: "ipv4hint",
    5: "echconfig",
    6: "ipv6hint",
}


class RdataSVCB:

    """SVCB RR RDATA Class"""

    def __init__(self, pkt, offset, rdlen):
        self.pkt = pkt
        self.offset = offset
        self.end_rdata = offset + rdlen
        self.rdata = pkt[offset:self.end_rdata]
        self.priority = None
        self.targetname = None
        self.params = []                            # list(key=value strings)
        self.decode()

    def decode(self):
        self.priority, = struct.unpack("!H", self.rdata[:2])
        d, self.offset = name_from_wire_message(self.pkt, self.offset+2)
        self.targetname = d.text()
        self.decode_params(self.pkt[self.offset:self.end_rdata])

    def decode_params(self, params_wire):
        lastkey = None
        while params_wire:
            pkey, plen = struct.unpack('!HH', params_wire[:4])
            pdata = params_wire[4:4+plen]
            pdata_text = None
            if lastkey is not None:
                if not pkey > lastkey:
                    print("ERROR: HTTPS RR keys are not in ascending order")
                else:
                    lastkey = pkey
            if pkey in SVCB_PARAM:
                pkey_text = SVCB_PARAM[pkey]
            else:
                pkey_text = "key{:d}".format(pkey)
            if pkey == 0:                                    ## mandatory
                keylist = []
                while pdata:
                    key = struct.unpack("!H", pdata[:2])
                    keylist.append(str(key))
                    pdata = pdata[2:]
                pdata_text = ','.join(keylist)
            elif pkey == 1:                                  ## alpn
                alpn_list = []
                while pdata:
                    alpn_len = pdata[0]
                    alpn = pdata[1:1+alpn_len].decode()
                    alpn_list.append(alpn)
                    pdata = pdata[1+alpn_len:]
                pdata_text = ','.join(alpn_list)
            elif pkey == 3:                                  ## port
                port = struct.unpack("!H", pdata[:2])
                pdata_text = str(port)
            elif pkey == 4:                                  ## ipv4hint
                ip4list = []
                while pdata:
                    ip4 = socket.inet_ntop(socket.AF_INET, pdata[:4])
                    ip4list.append(ip4)
                    pdata = pdata[4:]
                pdata_text = ','.join(ip4list)
            elif pkey == 6:                                  ## ipv6hint
                ip6list = []
                while pdata:
                    ip6 = socket.inet_ntop(socket.AF_INET6, pdata[:16])
                    ip6list.append(ip6)
                    pdata = pdata[16:]
                pdata_text = ','.join(ip6list)
            else:
                pdata_text = pdata.hex()
            if not pdata_text:
                self.params.append(pkey_text)
            else:
                self.params.append(("{}={}".format(pkey_text, pdata_text)))
            params_wire = params_wire[4+plen:]


    def __str__(self):
        return "%s %s %s" % (self.priority,
                             self.targetname,
                             " ".join(self.params))
