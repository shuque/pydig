"""
EDNS options

"""

import os
import socket
import struct
import math

from .options import options
from .common import ErrorMessage, EDNS0_UDPSIZE, PAD_BLOCK_SIZE
from .dnsparam import qt
from .name import name_from_text
from .util import h2bin


class OptRR:

    """EDNS OPT Resource Record; see RFC 2671 and 6891"""
    version = 0
    udpbufsize = EDNS0_UDPSIZE
    flags = 0
    dnssec_ok = False
    ercode = 0
    rrname = b'\x00'                                     # empty domain
    rrtype = struct.pack('!H', qt.get_val("OPT"))        # OPT type code
    rrclass = None
    rdlen = 0
    rdlen_packed = None
    rdata = b""
    pad_blocksize = PAD_BLOCK_SIZE

    def __init__(self, version, udpbufsize, flags, dnssec_ok):
        self.version = version
        self.udpbufsize = udpbufsize
        self.rrclass = struct.pack('!H', udpbufsize)
        self.dnssec_ok = dnssec_ok
        if flags != 0:
            self.flags = flags
        elif dnssec_ok:
            self.flags = 0x8000
        else:
            self.flags = 0x0
        if options["padding_blocksize"]:
            self.pad_blocksize = options["padding_blocksize"]
        return

    def mk_nsid(self):
        """Construct EDNS NSID option"""
        optcode = struct.pack('!H', 3)
        optlen = struct.pack('!H', 0)
        return optcode + optlen

    def mk_expire(self):
        """Construct EDNS Expire option"""
        optcode = struct.pack('!H', 9)
        optlen = struct.pack('!H', 0)
        return optcode + optlen

    def mk_client_subnet(self):
        """construct EDNS client subnet option"""
        prefix_addr, prefix_len = options["subnet"].split("/")
        prefix_len = int(prefix_len)
        addr_octets = int(math.ceil(prefix_len/8.0))
        if prefix_addr.find('.') != -1:                    # IPv4
            af = struct.pack('!H', 1)
            address = socket.inet_pton(socket.AF_INET,
                                       prefix_addr)[0:addr_octets]
        elif prefix_addr.find(':') != -1:                  # IPv6
            af = struct.pack('!H', 2)
            address = socket.inet_pton(socket.AF_INET6,
                                       prefix_addr)[0:addr_octets]
        else:
            raise ErrorMessage("Invalid client subnet: %s" % prefix_addr)
        src_prefix_len = struct.pack('B', prefix_len)
        scope_prefix_len = b'\x00'
        optcode = struct.pack('!H', 8)
        optdata = af + src_prefix_len + scope_prefix_len + address
        optlen = struct.pack('!H', len(optdata))
        return optcode + optlen + optdata

    def mk_cookie(self):
        """Construct EDNS cookie option"""
        optcode = struct.pack('!H', 10)
        if options["cookie"] is True:
            optdata = os.urandom(8)
            optlen = struct.pack('!H', 8)
        else:
            try:
                optdata = h2bin(options["cookie"])
            except:
                raise ErrorMessage("Malformed cookie: %s" % options["cookie"])
            optlen = struct.pack('!H', len(optdata))
        return optcode + optlen + optdata

    def mk_chainquery(self):
        """Construct EDNS chain query option"""
        optcode = struct.pack('!H', 13)
        if options["chainquery"] is True:
            optdata = b'\x00'
        else:
            optdata = name_from_text(options["chainquery"]).wire()
        optlen = struct.pack('!H', len(optdata))
        return optcode + optlen + optdata

    def mk_generic(self):
        """Construct generic EDNS options"""
        alldata = b''
        for (n, s) in options["ednsopt"]:
            optcode = struct.pack('!H', n)
            optdata = h2bin(s)
            optlen = struct.pack('!H', len(optdata))
            alldata += optcode + optlen + optdata
        return alldata

    def mk_padding(self, msgsize):
        """"
        Construct EDNS Padding option; see RFC 7830. Pads the DNS query
        message to the closest multiple of pad_blocksize.
        """
        remainder = msgsize % self.pad_blocksize
        if remainder == 0:
            print(";; Query Padding size: 0")
            return b''

        msgsize += 4     # account for 4 bytes of opt code + length
        remainder = msgsize % self.pad_blocksize
        optcode = struct.pack('!H', 12)
        padlen = self.pad_blocksize - remainder
        optdata = b'\x00' * padlen
        optlen = struct.pack('!H', len(optdata))
        print(";; Query Padding size: {}, Block size: {}".format(
            padlen+4, self.pad_blocksize))
        return optcode + optlen + optdata

    def mk_optrr(self, msglen):
        """Create EDNS0 OPT RR; see RFC 2671"""
        ttl = struct.pack('!BBH', self.ercode, self.version, self.flags)
        if options['nsid']:
            self.rdata += self.mk_nsid()
        if options['expire']:
            self.rdata += self.mk_expire()
        if options["cookie"]:
            self.rdata += self.mk_cookie()
        if options["subnet"]:
            self.rdata += self.mk_client_subnet()
        if options["chainquery"]:
            self.rdata += self.mk_chainquery()
        if options["ednsopt"]:
            self.rdata += self.mk_generic()
        if options["padding"]:
            msglen_no_pad = msglen + len(self.rrname) + 10 + len(self.rdata)
            self.rdata += self.mk_padding(msglen_no_pad)
        self.rdlen = len(self.rdata)
        self.rdlen_packed = struct.pack('!H', self.rdlen)
        return (self.rrname + self.rrtype + self.rrclass + ttl +
                self.rdlen_packed + self.rdata)
