#!/usr/bin/env python
#
# pydig: A small DNS query tool.
# 
# Copyright (C) 2006 - 2012, Shumon Huque
#
# pydig is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# pydig is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pydig; see the file COPYING.  If not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
#
# Author: Shumon Huque <shuque -@- upenn.edu>
# 

import os, sys, socket, struct, time, string, base64, hashlib, random

PROGNAME       = os.path.basename(sys.argv[0])
PROGDESC       = "a DNS query tool written in Python"
VERSION        = "0.5"
RESOLV_CONF    = "/etc/resolv.conf"    # where to find default server
DEFAULT_PORT   = 53
ITIMEOUT       = 0.5                   # initial timeout in seconds
RETRIES        = 3                     # how many times to try
BUFSIZE        = 4096                  # socket read/write buffer size
EDNS0_UDPSIZE  = 4096
DEBUG          = False                 # for more debugging output (-d)

count_compression = 0                  # count of compression pointers derefs

USAGE_STRING = """\
%s (%s), version %s

Usage: %s [list of options] <qname> [<qtype>] [<qclass>]
       %s @server +walk <zone>
Options:
        -h                        print program usage information
        @server                   server to query
        -pNN                      use port NN
        +tcp                      send query via TCP
        +aaonly                   set authoritative answer bit
        +cdflag                   set checking disabled bit
        +norecurse                set rd bit to 0 (recursion not desired)
        +edns0                    use EDNS0 with 4096 octet UDP payload
        +dnssec                   request DNSSEC RRs in response
        +hex                      print hexdump of rdata field
        +walk                     walk (enumerate) a DNSSEC secured zone
        +0x20                     randomize case of query name (bit 0x20 hack)
        -4                        perform queries using IPv4
        -6                        perform queries using IPv6
        -x                        reverse lookup of IPv4/v6 address in qname
        -d                        request additional debugging output
        -k/path/to/keyfile        use TSIG key in specified file
        -iNNN                     use specified message id
        -tNNN                     use this TSIG timestamp (secs since epoch)
        -y<alg>:<name>:<key>      use specified TSIG alg, name, key
""" \
% (PROGNAME, PROGDESC, VERSION, PROGNAME, PROGNAME)


def dprint(input):
    if DEBUG:        print "DEBUG:", input


class ErrorMessage(Exception):
    """A friendly error message."""
    name = PROGNAME
    def __str__(self):
        val = Exception.__str__(self)
        if val:
            return '%s: %s' % (self.name, val)
        else:
            return ''


class UsageError(ErrorMessage):
    """A command-line usage error."""
    def __str__(self):
        val = ErrorMessage.__str__(self)
        if val:
            return '%s\n%s' % (val, USAGE_STRING)
        else:
            return USAGE_STRING


def excepthook(exc_type, exc_value, exc_traceback):
    """Print tracebacks only for unexpected exceptions, not friendly errors."""
    if issubclass(exc_type, ErrorMessage):
        print >>sys.stderr, exc_value
    else:
        sys.__excepthook__(exc_type, exc_value, exc_traceback)


# Global dictionary of options: many options may be overridden or set in
# parse_args() by command line arguments.

options = dict(server=None, port=DEFAULT_PORT, use_tcp=False,
               aa=0, cd=0, rd=1, use_edns0=False, dnssec_ok=0,
               hexrdata=False, do_zonewalk=False, do_0x20=False,
               ptr=False, af=socket.AF_UNSPEC, do_tsig=False,
               tsig_file=None, tsig_sigtime=None, tsig_info=None,
               unsigned_messages="", msgid=None)

class DNSparam:
    """Class to encapsulate some DNS parameter types (type, class etc)"""

    def __init__(self, prefix, name2val):
        self.name2val = name2val
        self.val2name = dict([(y,x) for (x,y) in name2val.items()])
        self.prefix = prefix
        self.prefix_offset = len(prefix)
        
    def get_name(self, val):
        """given code (value), return text name of dns parameter"""
        if self.prefix:
            return self.val2name.get(val, "%s%d" % (self.prefix, val))
        else:
            return self.val2name[val]

    def get_val(self, name):
        """given text name, return code (value) of a dns parameter"""
        if self.prefix and name.startswith(self.prefix):
            return int(name[self.prefix_offset:])
        else:
            return self.name2val[name]

# Instantiate the DNS parameter classes at the module level, since they
# are used by a variety of module routines.

qt = DNSparam("TYPE",
              dict(A=1, NS=2, CNAME=5, SOA=6, PTR=12, MX=15, TXT=16, SIG=24,
                   KEY=25, AAAA=28, NXT=30, SRV=33, NAPTR=35, CERT=37, A6=38,
                   DNAME=39, OPT=41, DS=43, SSHFP=44, IPSECKEY=45, RRSIG=46,
                   NSEC=47, DNSKEY=48, DHCID=49, NSEC3=50, NSEC3PARAM=51,
                   HIP=55, SPF=99, AXFR=252, TKEY=249, TSIG=250, ANY=255,
                   TA=32768, DLV=32769))

qc = DNSparam("CLASS",
              dict(IN=1, CH=3, HS=4, ANY=255))

rc = DNSparam("RCODE",
              dict(NOERROR=0, FORMERR=1, SERVFAIL=2, NXDOMAIN=3, NOTIMPL=4,
                   REFUSED=5, NOTAUTH=9, BADVERS=16, BADKEY=17, BADTIME=18,
                   BADMODE=19, BADNAME=20, BADALG=21, BADTRUNC=22))
                
dnssec_proto = { 0:"Reserved", 1:"TLS", 2:"Email", 3:"DNSSEC", 4:"IPSEC" }

dnssec_alg = { 0:"Reserved", 1:"RSAMD5", 2:"DH", 3:"DSA", 4:"ECC",
               5:"RSASHA1", 6:"DSA-NSEC3-SHA1", 7:"RSASHA1-NSEC3-SHA1",
               8:"RSASHA256", 10:"RSASHA512", 12:"ECC-GOST" }

dnssec_digest = { 1:"SHA-1", 2:"SHA-256" }              # see RFC 4509

sshfp_alg = { 1:"RSA", 2:"DSS" }                        # see RFC 4255

sshfp_fptype = { 1:"SHA-1" }                            # see RFC 4255

# TSIG algorithms: see RFC 2845 (hmac-md5), 3645 (gss-tsig), 4635 (hmac-sha*)
# So far, pydig implements only the most commonly used hmac-md5.
dns_tsig_alg = { "hmac-md5"    : "hmac-md5.sig-alg.reg.int.",
                 "gss-tsig"    : "gss-tsig.",
                 "hmac-sha1"   : "hmac-sha1.",
                 "hmac-sha224" : "hmac-sha224.",
                 "hmac-sha256" : "hmac-sha256.",
                 "hmac-sha384" : "hmac-sha384.",
                 "hmac-sha512" : "hmac-sha512." }

class Struct:
    "Just to emulate C struct or record ..."
    pass

class Tsig:
    """TSIG Object Class: encapsulates TSIG related methods and data"""
    def __init__(self):
        self.keyname = None
        self.key = None
        self.algorithm = None
        self.prior_digest = None
        self.sigtime = None
        self.request = Struct()
        self.request.fudge = 300
        self.request.msgid = None
        self.request.tsig_mac = None
        self.request.tsig_rr = None
        self.request.mac = None
        self.request.tsig = None
        self.response = Struct()
        self.response.msg = None
        self.response.tsig_offset = None
        self.tsig_total = 0
        self.verify_success = 0
        self.verify_failure = 0

    def setkey(self, name, key, algorithm="hmac-md5"):
        self.keyname = name
        self.key = key
        if algorithm != "hmac-md5":
            raise ErrorMessage("Only hmac-md5 TSIG algorithm supported.")
        self.algorithm = dns_tsig_alg.get(algorithm)

    def mk_request_tsig(self, msgid, msg):
        """Create TSIG (Transaction Signature) RR; see RFC 2845; currently
        only supports the HMAC-MD5 signature algorithm."""

        # strictly speaking, we only need tsig name/alg in canonical form
        # for the MAC computation, but we'll use them in the RR also ..
        tsig_name = txt2domainname(self.keyname, canonical_form=True)
        tsig_type = struct.pack('!H', qt.get_val("TSIG"))
        tsig_class = struct.pack('!H', qc.get_val("ANY"))
        tsig_ttl = struct.pack('!I', 0)
        tsig_alg = txt2domainname(self.algorithm, canonical_form=True)
        if options["tsig_sigtime"]:
            now = options["tsig_sigtime"]
        else:
            now = int(time.time())
        tsig_sigtime = mk_tsig_sigtime(now)
        tsig_fudge = struct.pack('!H', self.request.fudge)
        tsig_error = struct.pack('!H', 0)                     # NOERROR
        tsig_otherlen = struct.pack('!H', 0)
        data = "%s%s%s%s%s%s%s%s%s" % (msg, tsig_name, tsig_class, tsig_ttl,
                                       tsig_alg, tsig_sigtime, tsig_fudge,
                                       tsig_error, tsig_otherlen)
        mac = hmac_md5(self.key, data)
        mac_size = struct.pack('!H', len(mac))
        self.request.mac = mac
        self.origid = struct.pack('!H', msgid)
        rdata = "%s%s%s%s%s%s%s%s" % (tsig_alg, tsig_sigtime, tsig_fudge,
                                      mac_size, mac, self.origid, tsig_error,
                                      tsig_otherlen)
        rdlen = struct.pack('!H', len(rdata))
        self.request.tsig = "%s%s%s%s%s%s" % \
                            (tsig_name, tsig_type, tsig_class, tsig_ttl,
                             rdlen, rdata)
        return self.request.tsig
    
    def decode_tsig_rdata(self, pkt, offset, rdlen, tsig_name, tsig_offset):
        """decode TSIG rdata: alg, sigtime, fudge, mac_size, mac, origid,
        error, otherlen; see RFC 2845"""

        self.tsig_total += 1
        self.response.msg = pkt
        self.response.tsig_offset = tsig_offset
        self.response.tsig_name = tsig_name
        d, offset = get_domainname(pkt, offset)
        self.response.alg = pdomainname(d)
        if self.response.alg.lower() != self.algorithm:
            raise ErrorMessage("%s -- unexpected TSIG algorithm" %
                               self.response.alg)
        self.response.sigtime = packed2int(pkt[offset:offset+6])
        offset += 6
        self.response.fudge, self.response.mac_size = \
                             struct.unpack("!HH", pkt[offset:offset+4])
        offset += 4
        self.response.mac = pkt[offset:offset+self.response.mac_size]
        mac_base64 = base64.standard_b64encode(self.response.mac)
        offset += self.response.mac_size
        self.response.origid, self.response.error, self.response.otherlen \
                              = struct.unpack("!HHH", pkt[offset:offset+6])
        offset += 6
        result = "%s %ld %d %d %s %d %s %d" % \
                 (self.response.alg,
                  self.response.sigtime,
                  self.response.fudge,
                  self.response.mac_size,
                  mac_base64,
                  self.response.origid,
                  rc.get_name(self.response.error),
                  self.response.otherlen)
        if self.response.otherlen != 0:          # only for BADTIME ercode
            self.response.otherdata = str(pkt[offset:offset+otherlen])
            result += self.response.otherdata
        else:
            self.response.otherdata = ""
        self.verify_tsig()
        return result

    def verify_tsig(self):
        """Verify TSIG record if possible; see RFC 2845, Section 3.4 & 4
        Reconstruct packet before TSIG record was added, and with origid;
        add TSIG variables, and request MAC; compute digest and compare it
        with received digest."""
    
        if not domain_name_match(self.response.tsig_name, self.keyname):
            raise ErrorMessage("encountered unknown TSIG key name: %s" %
                               self.response.tsig_name)

        request_mac = "%s%s" % \
                      (struct.pack('!H', len(self.request.mac)),
                       self.request.mac)

        data = self.response.msg[:self.response.tsig_offset]
        arcount, = struct.unpack('!H', data[10:12])
        dns_message = "%s%s%s%s" % \
                      (struct.pack('!H', self.response.origid), data[2:10],
                       struct.pack('!H', arcount-1), data[12:])

        tsig_name = txt2domainname(self.response.tsig_name,
                                   canonical_form=True)
        tsig_class = struct.pack('!H', qc.get_val("ANY"))
        tsig_ttl = struct.pack('!I', 0)
        tsig_alg = txt2domainname(self.algorithm, canonical_form=True)
        tsig_sigtime = mk_tsig_sigtime(self.response.sigtime)
        tsig_fudge = struct.pack('!H', self.response.fudge)
        tsig_error = struct.pack('!H', self.response.error)
        tsig_otherlen = struct.pack('!H', self.response.otherlen)
        tsig_otherdata = self.response.otherdata
        tsig_vars = "%s%s%s%s%s%s%s%s%s" % \
                    (tsig_name, tsig_class, tsig_ttl, tsig_alg, tsig_sigtime,
                     tsig_fudge, tsig_error, tsig_otherlen, tsig_otherdata)

        if self.prior_digest:
            input_data = "%s%s%s%s%s%s" % \
                         (struct.pack('!H', len(self.prior_digest)),
                          self.prior_digest,
                          options["unsigned_messages"],
                          dns_message, tsig_sigtime, tsig_fudge)
        else:
            input_data = "%s%s%s" % \
                         (request_mac, dns_message, tsig_vars)
        computed_mac = hmac_md5(self.key, input_data)
        if computed_mac != self.response.mac:
            print "WARNING: TSIG record verification failed."
            self.verify_failure += 1
        else:
            self.verify_success += 1
        if abs(self.response.sigtime - int(time.time())) > self.request.fudge:
            print "WARNING: TSIG signature time exceeds clock skew."

        self.prior_digest = self.response.mac          # for AXFR
        return


def parse_args(arglist):
    """Parse command line arguments. Options must come first."""

    global DEBUG
    qtype = "A"
    qclass = "IN"
    
    i=0
    for (i, arg) in enumerate(arglist):
        if arg.startswith('@'):            options["server"] = arg[1:]
        elif arg == "-h":                  raise UsageError()
        elif arg.startswith("-p"):         options["port"] = int(arg[2:])
        elif arg == "+tcp":                options["use_tcp"] = True
        elif arg == "+aaonly":             options["aa"] = 1
        elif arg == "+cdflag":             options["cd"] = 1
        elif arg == "+norecurse":          options["rd"] = 0
        elif arg == "+edns0":              options["use_edns0"] = True
        elif arg == "+dnssec":             options["dnssec_ok"] = 1; options["use_edns0"] = True
        elif arg == "+hex":                options["hexrdata"] = True
        elif arg == "+walk":               options["do_zonewalk"] = True
        elif arg == "+0x20":               options["do_0x20"] = True
        elif arg == "-4":                  options["af"] = socket.AF_INET
        elif arg == "-6":                  options["af"] = socket.AF_INET6
        elif arg == "-x":                  options["ptr"] = True
        elif arg == "-d":                  DEBUG = True
        elif arg.startswith("-k"):         options["tsig_file"] = arg[2:]
        elif arg.startswith("-i"):         options["msgid"] = int(arg[2:])
        elif arg.startswith("-t"):         options["tsig_time"] = int(arg[2:])
        elif arg.startswith("-y"):         options["tsig_info"] = arg[2:]
        else:
            break

    if not options["server"]:         # use 1st server listed in resolv.conf
        for line in open(RESOLV_CONF):
            if line.startswith("nameserver"):
                options["server"] = line.split()[1]
                break
        else:
            raise ErrorMessage("Couldn't find a default server in %s" %
                               RESOLV_CONF)

    if options["tsig_file"]:
        name, key = read_tsig_params(options["tsig_file"])
        tsig.setkey(name, key)
        options["do_tsig"] = True

    # for TSIG, -y overrides -k, if both are specified
    if options["tsig_info"]:
        alg, name, key = options["tsig_info"].split(":")
        key = base64.decodestring(key)
        tsig.setkey(name, key, alg)
        options["do_tsig"] = True

    qname = arglist[i]

    if not options["do_zonewalk"]:
        if arglist[i+1:]:           qtype = arglist[i+1].upper()
        if arglist[i+2:]:           qclass = arglist[i+2].upper()

    if options["ptr"]:
        qname = ip2ptr(qname); qtype = "PTR"; qclass = "IN"
    else:
        if not qname.endswith("."): qname += "."

    return (qname, qtype, qclass)

    
def hexdump(input, separator=' '):
    """return a hexadecimal representation of the given string"""
    hexlist = ["%02x" % ord(x) for x in input]
    return separator.join(hexlist)


def packed2int(input):
    """convert arbitrary sized bigendian packed string into an integer"""
    sum = 0
    for (i, x) in enumerate(input[::-1]):
        sum += ord(x) * 2**(8*i)
    return sum


def randomize_case(input):
    """randomize case of input string; using the bit 0x20 hack to
    improve input entropy: see draft-vixie-dns-0x20-00"""
    outlist = []
    random.seed()
    for c in input:
        if c.isalpha():
            if random.choice([0,1]):
                outlist.append(chr((ord(c) ^ 0x20)))
                continue
        outlist.append(c)
    return "".join(outlist)


def domain_name_match(s1, s2, case_sensitive=False):
    if case_sensitive:
        return (s1 == s2)
    else:
        return (s1.lower() == s2.lower())
    

def mk_id():
    """Return a 16-bit ID number to be used by the DNS request packet"""
    if options["msgid"]:
        return options["msgid"]
    else:
        random.seed()
        return random.randint(1,65535)


def ip2ptr(address):
    """return PTR owner name of an IPv4 or IPv6 address (for -x option)"""
    v4_suffix = '.in-addr.arpa.'
    v6_suffix = '.ip6.arpa.'
    error = False
    try:
        if address.find('.') != -1:                             # IPv4 address
            packed = socket.inet_pton(socket.AF_INET, address)
            octetlist = ["%d" % ord(x) for x in packed]
            ptrowner = "%s%s" % ('.'.join(octetlist[::-1]), v4_suffix)
        elif address.find(':') != -1:                           # IPv6 address
            packed = socket.inet_pton(socket.AF_INET6, address)
            hexstring = ''.join(["%02x" % ord(x) for x in packed])
            ptrowner = "%s%s" % \
                       ('.'.join([x for x in hexstring[::-1]]), v6_suffix)
        else:
            error = True
    except socket.error:
        error = True
    if error:
        raise ErrorMessage("%s isn't an IPv4 or IPv6 address" % address)
    
    return ptrowner


def get_socketparams(server, port, af, type):
    """Only the first set of parameters is used. Passing af=AF_UNSPEC prefers
    IPv6 if possible."""
    ai = socket.getaddrinfo(server, port, af, type)[0]
    family, socktype, proto, canonname, sockaddr = ai
    server_addr, port = sockaddr[0:2]
    return (server_addr, port, family, socktype)

    
def send_request_udp(pkt, host, port, family, itimeout, retries):
    """Send the request via UDP, with retries using exponential backoff"""
    gotresponse = False
    responsepkt, responder_addr = "", ("", 0)
    s = socket.socket(family, socket.SOCK_DGRAM)
    timeout = itimeout
    while (retries > 0):
        s.settimeout(timeout)
        try:
            s.sendto(pkt, (host, port))
            (responsepkt, responder_addr) = s.recvfrom(BUFSIZE)
            gotresponse = True
        except socket.timeout:
            timeout = timeout * 2
            dprint("Request timed out with no answer")
            pass
        retries -= 1
        if gotresponse:
            break
    s.close()
    return (responsepkt, responder_addr)


def send_request_tcp(pkt, host, port, family):
    """Send the request packet via TCP"""

    # prepend 2-byte length field, per RFC 1035 Section 4.2.2
    pkt = struct.pack("!H", len(pkt)) + pkt
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        s.send(pkt)
        response = s.recv(BUFSIZE)
    except socket.error, diag:
        s.close()
        raise ErrorMessage("tcp socket error: %s" % diag)
    s.close()
    return response
        

def do_axfr(pkt, host, port, family):
    """AXFR uses TCP, and is answered by a sequence of response messages."""

    # prepend 2-byte length field, per RFC 1035 Section 4.2.2
    pkt = struct.pack("!H", len(pkt)) + pkt
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        s.send(pkt)
        s.settimeout(1.0)        # setting non-blocking is often too aggressive
        Done = False
        response = ""
        readSoFar = 0
        while not Done:
            chunk = s.recv(BUFSIZE)
            chunklen = len(chunk)
            if chunklen == 0:
                Done = True
                continue
            response += chunk
            readSoFar += chunklen
    except socket.timeout:
        pass                     # end of data
    except socket.error, diag:
        s.close()
        raise ErrorMessage("tcp socket error: %s" % diag)
    s.close()

    return (response, readSoFar)


def decode_axfr(response, resplen):
    """given a string containing a sequence of response messages from
    an AXFR request, decode and print only the answer RRs"""
    rrtotal = 0
    msgtotal = 0
    msgsizes = dict(max=-1, min=0, avg=0, total=0)
    p = response
    while p:
        msglen, = struct.unpack('!H', p[0:2])
        msgtotal += 1
        if msgsizes["max"] == -1:
            msgsizes["max"] = msglen
            msgsizes["min"] = msglen
        else:
            if msglen > msgsizes["max"]: msgsizes["max"] = msglen
            if msglen < msgsizes["min"]: msgsizes["min"] = msglen
        msgsizes["total"] += msglen
        msg = p[2:2+msglen]
        answerid, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, \
                  qdcount, ancount, nscount, arcount = \
                  decode_header(msg, -1, checkid=False)
        if rcode != 0:
            raise ErrorMessage("Zone transfer failed: %s" % rc.get_name(rcode))
        
        offset = 12                     # skip over DNS header

        for i in range(qdcount):
            domainname, rrtype, rrclass, offset = decode_question(msg, offset)

        for i in range(ancount):
            domainname, rrtype, rrclass, ttl, rdata, offset = \
                        decode_rr(msg, offset, False)
            print "%s\t%d\t%s\t%s\t%s" % \
                  (pdomainname(domainname), ttl,
                   qc.get_name(rrclass), qt.get_name(rrtype), rdata)
        rrtotal += ancount
        
        # For AXFR, we don't care about the authority & additional sections.
        # However, if using TSIG, we want to decode and verify the TSIG
        # pseudo RR in the additional section if present.

        tsig_seen = False
        for section, rrcount in \
            [("authority", nscount), ("additional", arcount)]:
            if rrcount == 0: continue
            for i in range(rrcount):
                domainname, rrtype, rrclass, ttl, rdata, offset = \
                            decode_rr(msg, offset, False)
                if rrtype == 250:            # should decode and verify here
                    tsig_seen = True
                    print "%s\t%d\t%s\t%s\t%s" % \
                          (pdomainname(domainname), ttl,
                           qc.get_name(rrclass), qt.get_name(rrtype), rdata)
                    unsigned_messages = ""
        if options["do_tsig"] and (not tsig_seen):
            options["unsigned_messages"] += msg
        p = p[2+msglen:]

    print "\n;; Total RRs transferred: %d, Total messages: %d" % \
          (rrtotal, msgtotal)
    print ";; Message sizes: %d max, %d min, %d average" % \
          (msgsizes["max"], msgsizes["min"], msgsizes["total"]/msgtotal)
    if options["do_tsig"]:
        print ";; TSIG records: %d, success: %d, failure: %d" % \
              (tsig.tsig_total, tsig.verify_success, tsig.verify_failure)
    return
        

def mk_optrr(edns_version, udp_payload, dnssec_ok):
    """Create EDNS0 OPT RR with udp_payload advertisement; see RFC 2671"""
    rrname    = '\x00'                                   # empty domain
    rrtype    = struct.pack('!H', qt.get_val("OPT"))     # OPT type code
    rrclass = struct.pack('!H', udp_payload)             # udp payload
    if dnssec_ok: z = 0x8000
    else:         z = 0x0
    ttl   = struct.pack('!BBH', 0, edns_version, z)      # extended rcode
    rdlen = struct.pack('!H', 0)                         # rdlen=0
    return "%s%s%s%s%s" % (rrname, rrtype, rrclass, ttl, rdlen)


def print_optrr(rrclass, ttl, rdata):
    """decode and print EDNS0 OPT pseudo RR; see RFC 2671"""
    packed_ttl = struct.pack('!I', ttl)
    ercode, version, z = struct.unpack('!BBH', packed_ttl)
    flags = []
    if z & 0x8000: flags.append("do")                  # DNSSEC OK bit
    print ";; OPT pseudo RR: edns_version=%d, udp_payload=%d, flags=%s, ercode=%d" % \
          (version, rrclass, ' '.join(flags), ercode)


def mk_request(qname, qtype_val, qclass, id, options):
    """Construct DNS query packet, given various parameters"""
    packed_id = struct.pack('!H', id)
    qr = 0                                      # query/response
    opcode = 0                                  # standard query
    aa = options["aa"]                          # authoritative answer
    tc = 0                                      # truncated response
    rd = options["rd"]                          # recursion desired
    ra = 0                                      # recursion available
    z = 0                                       # reserved
    ad = 0                                      # authenticated data
    cd = options["cd"]                          # checking disabled
    rcode = 0                                   # response code
    qdcount = struct.pack('!H', 1)              # 1 question
    ancount = struct.pack('!H', 0)              # 0 answer
    nscount = struct.pack('!H', 0)              # 0 authority

    if options["use_edns0"]:
        arcount = struct.pack('!H', 1)
        additional = mk_optrr(0, EDNS0_UDPSIZE, options["dnssec_ok"])
    else:
        arcount = struct.pack('!H', 0)
        additional = ""

    flags = (qr << 15) + (opcode << 11) + (aa << 10) + (tc << 9) + \
            (rd << 8) + (ra << 7) + (z << 6) + (ad << 5) + (cd << 4) + rcode
    flags = struct.pack('!H', flags)

    wire_qname = txt2domainname(qname)          # wire format domainname

    question = "%s%s%s" % (wire_qname, struct.pack('!H', qtype_val),
                           struct.pack('!H', qclass))
        
    msg = "%s%s%s%s%s%s%s%s" % \
          (packed_id, flags, qdcount, ancount, nscount, arcount,
           question, additional)

    if options["do_tsig"]:                      # sign message with TSIG
        tsig_rr = tsig.mk_request_tsig(id, msg)
        arcount, = struct.unpack('!H', arcount)
        arcount = struct.pack('!H', arcount+1)
        additional = "%s%s" % (additional, tsig_rr)
        msg = "%s%s%s%s%s%s%s%s" % \
              (packed_id, flags, qdcount, ancount, nscount, arcount,
               question, additional)
    
    return msg


def read_tsig_params(filename):
    """Read TSIG key parameters from file containing a single KEY record"""
    line = open(filename).readline()
    line_parts = line.split()
    tsig_name = line_parts[0]
    tsig_key = ''.join(line_parts[6:])
    dprint("read tsigkey %s %s" % (tsig_name, tsig_key))
    tsig_key = base64.decodestring(tsig_key)
    return (tsig_name, tsig_key)


def mk_tsig_sigtime(sigtime):
    """make 48-bit TSIG signature time field; see RFC 2845"""
    """this will need to be updated before Jan 19th 2038 :-)"""
    return '\x00\x00' + struct.pack('!I', sigtime)  # 48-bits


def xor_string(a, b):
    """bitwise XOR bytes in a and b and return concatenated result"""
    result = ''
    for (x, y) in zip(a, b):
        result += chr(ord(x) ^ ord(y))
    return result

                                
def hmac_md5(key, data):
    """HMAC-MD5 algorithm; see RFC 2104"""
    BLOCKSIZE = 64                             # 64 bytes = 512 bits
    ipad = '\x36' * BLOCKSIZE
    opad = '\x5c' * BLOCKSIZE

    key = "%s%s" % (key, '\x00' * (BLOCKSIZE - len(key)))  # pad to blocksize

    m = hashlib.md5()
    m.update("%s%s" % (xor_string(key, ipad), data))
    r1 = m.digest()

    m = hashlib.md5()
    m.update("%s%s" % (xor_string(key, opad), r1))

    return m.digest()


def decode_header(pkt, sentid, checkid=True):
    """Decode a DNS protocol header"""
    answerid, answerflags, qdcount, ancount, nscount, arcount = \
              struct.unpack('!HHHHHH', pkt[:12])
    if checkid and (answerid != sentid):
        # probably should continue listening for a valid response
        # rather than bailing out here ..
        raise ErrorMessage("got response with id: %ld (expecting %ld)" % 
                           (answerid, sentid))

    qr = answerflags >> 15
    opcode = (answerflags >> 11) & 0xf
    aa = (answerflags >> 10) & 0x1
    tc = (answerflags >> 9) & 0x1
    rd = (answerflags >> 8) & 0x1
    ra = (answerflags >> 7) & 0x1
    z  = (answerflags >> 6) & 0x1
    ad = (answerflags >> 5) & 0x1
    cd = (answerflags >> 4) & 0x1
    rcode = (answerflags) & 0xf

    return (answerid, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode,
            qdcount, ancount, nscount, arcount)


def txt2domainname(input, canonical_form=False):
    """turn textual representation of a domain name into it's wire format"""
    if input == ".":
        d = '\x00'
    else:
        d = ""
        for label in input.split('.'):
            if canonical_form:
                label = label.lower()
            length = len(label)
            d += struct.pack('B', length) + label
    return d


def get_domainname(pkt, offset):
    """decode a domainname at the given packet offset; see RFC 1035"""
    global count_compression
    labellist = []               # a domainname is a sequence of labels
    Done = False
    while not Done:
        llen, = struct.unpack('B', pkt[offset])
        if (llen >> 6) == 0x3:                 # compression pointer, sec 4.1.4
            count_compression += 1
            c_offset, = struct.unpack('!H', pkt[offset:offset+2])
            c_offset = c_offset & 0x3fff       # last 14 bits
            offset +=2
            rightmostlabels, junk = get_domainname(pkt, c_offset)
            labellist += rightmostlabels
            Done = True
        else:
            offset += 1
            label = pkt[offset:offset+llen]
            offset += llen
            labellist.append(label)
            if llen == 0:
                Done = True
    return (labellist, offset)


def pdomainname(labels):
    """given a sequence of domainname labels, return a printable string"""
    if len(labels) == 1:          # list with 1 empty label is the root
        return "."
    else:
        return ".".join(labels)


def decode_question(pkt, offset):
    """decode question section of a DNS message"""
    domainname, offset = get_domainname(pkt, offset)
    rrtype, rrclass = struct.unpack("!HH", pkt[offset:offset+4])
    offset += 4
    return (domainname, rrtype, rrclass, offset)


def generic_rdata_encoding(rdata, rdlen):
    """return generic encoding of rdata for unknown types; see RFC 3597"""
    return "\# %d %s" % (rdlen, hexdump(rdata, separator=''))

    
def decode_txt_rdata(rdata, rdlen):
    """decode TXT RR rdata into a string of quoted text strings,
    escaping any embedded double quotes"""
    txtstrings = []
    position = 0
    while position < rdlen:
        slen, = struct.unpack('B', rdata[position])
        s = rdata[position+1:position+1+slen]
        s = '"%s"' % s.replace('"', '\\"')
        txtstrings.append(s)
        position += 1 + slen
    return ' '.join(txtstrings)


def decode_soa_rdata(pkt, offset, rdlen):
    """decode SOA rdata: mname, rname, serial, refresh, retry, expire, min"""
    d, offset = get_domainname(pkt, offset)
    mname = pdomainname(d)
    d, offset = get_domainname(pkt, offset)
    rname = pdomainname(d)
    serial, refresh, retry, expire, min = \
            struct.unpack("!IiiiI", pkt[offset:offset+20])
    return "%s %s %d %d %d %d %d" % \
           (mname, rname, serial, refresh, retry, expire, min)
    

def decode_srv_rdata(pkt, offset):
    """decode SRV rdata: priority (2), weight (2), port, target; RFC 2782"""
    priority, weight, port = struct.unpack("!HHH", pkt[offset:offset+6])
    d, offset = get_domainname(pkt, offset+6)
    target = pdomainname(d)
    return "%d %d %d %s" % (priority, weight, port, target)


def decode_sshfp_rdata(pkt, offset, rdlen):
    """decode SSHFP rdata: alg, fp_type, fingerprint; see RFC 4255"""
    alg, fptype = struct.unpack('BB', pkt[offset:offset+2])
    fingerprint = hexdump(pkt[offset+2:offset+rdlen], separator='')
    if DEBUG:
        rdata = "%d(%s) %d(%s) %s" % \
                (alg, sshfp_alg.get(alg, "unknown"),
                 fptype, sshfp_fptype.get(fptype, "unknown"), fingerprint)
    else:
        rdata = "%d %d %s" % (alg, fptype, fingerprint)
    return rdata


def decode_naptr_rdata(pkt, offset, rdlen):
    """decode NAPTR: order, pref, flags, svc, regexp, replacement; RFC 2915"""
    param = {}
    order, pref = struct.unpack('!HH', pkt[offset:offset+4])
    position = offset+4
    for name in ["flags", "svc", "regexp"]:
        slen, = struct.unpack('B', pkt[position])
        s = pkt[position+1:position+1+slen]
        param[name] = '"%s"' % s.replace('\\', '\\\\')
        position += (1+slen)
    d, junk = get_domainname(pkt, position)
    replacement = pdomainname(d)
    return "%d %d %s %s %s %s" % (order, pref, param["flags"], param["svc"],
                                  param["regexp"], replacement)


def decode_ipseckey_rdata(pkt, offset, rdlen):
    """decode IPSECKEY rdata; see RFC 4025"""
    prec, gwtype, alg = struct.unpack('BBB', pkt[offset:offset+3])
    position = offset+3
    if gwtype == 0:                            # no gateway present
        gw = "."
    elif gwtype == 1:                          # 4-byte IPv4 gw
        gw = socket.inet_ntop(socket.AF_INET, pkt[position:position+4])
        position += 4
    elif gwtype == 2:                          # 16-byte IPv6 gw
        gw = socket.inet_ntop(socket.AF_INET6, pkt[position:position+16])
        position += 16
    elif gwtype == 3:                          # domainname
        d, position = get_domainname(pkt, position)
        gw = pdomainname(d)
    if alg == 0:                               # no public key
        pubkey = ""
    else:
        pubkeylen = rdlen - (position - offset)
        pubkey = base64.standard_b64encode(pkt[position:position+pubkeylen])
    return "%d %d %d %s %s" % (prec, gwtype, alg, gw, pubkey)


def decode_dnskey_rdata(pkt, offset, rdlen):
    """decode DNSKEY rdata: flags, proto, alg, pubkey; see RFC 4034"""
    flags, proto, alg = struct.unpack('!HBB', pkt[offset:offset+4])
    pubkey = pkt[offset+4:offset+rdlen]
    if DEBUG:
        zonekey = (flags >> 8) & 0x1;         # bit 7
        sepkey = flags & 0x1;                 # bit 15
        if alg == 5:                          # RSA/SHA1 algorithm (RFC 3110)
            if pubkey[0] == '\x00':   # length field is 3 octets
                elen, = struct.unpack('!H', pubkey[1:3])
                exponent = packed2int(pubkey[1:1+elen])
            else:
                elen, = struct.unpack('B', pubkey[0])
                exponent = packed2int(pubkey[1:1+elen])
        else:
            exponent=0
        result = "%d %d(%s) %d(%s) e=%d %s" % \
                 (flags, proto, dnssec_proto[proto], alg, dnssec_alg[alg],
                  exponent, base64.standard_b64encode(pubkey))
    else:
        result = "%d %d %d %s" % \
                 (flags, proto, alg, base64.standard_b64encode(pubkey))
    return result


def decode_ds_rdata(pkt, offset, rdlen):
    """decode DS rdata: keytag, alg, digesttype, digest; see RFC 4034"""
    keytag, alg, digesttype = struct.unpack('!HBB', pkt[offset:offset+4])
    digest = hexdump(pkt[offset+4:offset+rdlen], separator='')
    if DEBUG:
        result = "%d %d(%s) %d(%s) %s" % \
                 (keytag, alg, dnssec_alg[alg], digesttype,
                  dnssec_digest[digesttype], digest)
    else:
        result = "%d %d %d %s" % (keytag, alg, digesttype, digest)
    return result


def decode_rrsig_rdata(pkt, offset, rdlen):
    """decode RRSIG rdata; see RFC 4034"""
    end_rdata = offset + rdlen
    type_covered, alg, labels, orig_ttl, sig_exp, sig_inc, keytag = \
          struct.unpack('!HBBIIIH', pkt[offset:offset+18])
    sig_exp = time.strftime("%Y%m%d%H%M%S", time.gmtime(sig_exp))
    sig_inc = time.strftime("%Y%m%d%H%M%S", time.gmtime(sig_inc))
    d, offset = get_domainname(pkt, offset+18)
    signer_name = pdomainname(d)
    signature = pkt[offset:end_rdata]
    return "%s %d %d %d %s %s %d %s %s" % \
           (qt.get_name(type_covered), alg, labels, orig_ttl,
            sig_exp, sig_inc, keytag, signer_name,
            base64.standard_b64encode(signature))


def decode_typebitmap(windownum, bitmap):
    """decode NSEC style type bitmap into list of RR types; see RFC 4034"""
    rrtypelist = []
    for (charpos, c) in enumerate(bitmap):
        value, = struct.unpack('B', c)
        for i in range(8):
            isset = (value << i) & 0x80
            if isset:
                bitpos = (256 * windownum) + (8 * charpos) + i
                rrtypelist.append(qt.get_name(bitpos))
    return rrtypelist


def decode_nsec_rdata(pkt, offset, rdlen):
    """decode NSEC rdata: nextrr, type-bitmap; see RFC 4034"""
    end_rdata = offset + rdlen
    d, offset = get_domainname(pkt, offset)
    nextrr = pdomainname(d)
    type_bitmap = pkt[offset:end_rdata]
    p = type_bitmap
    rrtypelist = []
    while p:
        windownum, winlen = struct.unpack('BB', p[0:2])
        bitmap = p[2:2+winlen]
        rrtypelist += decode_typebitmap(windownum, bitmap)
        p = p[2+winlen:]
    return "%s %s" % (nextrr, ' '.join(rrtypelist))


def decode_nsec3param_rdata(pkt, offset, rdlen):
    """decode NSEC3PARAM rdata: hash, flags, iterations, salt len, salt;
    see RFC 5155 Section 4.2"""
    
    hashalg, flags, iterations, saltlen = struct.unpack('!BBHB',
                                                        pkt[offset:offset+5])
    salt = hexdump(pkt[offset+5:offset+5+saltlen], separator='')
    result = "%d %d %d %s" % (hashalg, flags, iterations, salt)
    return result


def decode_nsec3_rdata(pkt, offset, rdlen):
    """decode NSEC3 rdata; see RFC 5155 Section 3"""

    # Translation table for normal base32 to base32 with extended hex
    # alphabet used by NSEC3 (see RFC 4648, Section 7). This alphabet
    # has the property that encoded data maintains its sort order when
    # compared bitwise.
    b32_to_ext_hex = string.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                                      '0123456789ABCDEFGHIJKLMNOPQRSTUV')

    end_rdata = offset + rdlen
    hashalg, flags, iterations, saltlen = struct.unpack('!BBHB',
                                                        pkt[offset:offset+5])
    salt = hexdump(pkt[offset+5:offset+5+saltlen], separator='')
    offset += (5 + saltlen)
    hashlen, = struct.unpack('!B', pkt[offset:offset+1])
    offset += 1
    # hashed next owner name, base32 encoded with extended hex alphabet
    hashed_next_owner = base64.b32encode(pkt[offset:offset+hashlen])
    hashed_next_owner = hashed_next_owner.translate(b32_to_ext_hex)
    offset += hashlen
    type_bitmap = pkt[offset:end_rdata]
    p = type_bitmap
    rrtypelist = []
    while p:
        windownum, winlen = struct.unpack('BB', p[0:2])
        bitmap = p[2:2+winlen]
        rrtypelist += decode_typebitmap(windownum, bitmap)
        p = p[2+winlen:]
    rrtypes = ' '.join(rrtypelist)
    result = "%d %d %d %s %s %s" % \
             (hashalg, flags, iterations, salt, hashed_next_owner, rrtypes)
    return result


def decode_rr(pkt, offset, hexrdata):
    """ Decode a resource record, given DNS packet and offset"""

    orig_offset = offset
    domainname, offset = get_domainname(pkt, offset)
    rrtype, rrclass, ttl, rdlen = \
            struct.unpack("!HHIH", pkt[offset:offset+10])
    offset += 10
    rdata = pkt[offset:offset+rdlen]
    if hexrdata:
        rdata = hexdump(rdata)
    elif rrtype == 1:                                        # A
        rdata = socket.inet_ntop(socket.AF_INET, rdata)
    elif rrtype in [2, 5, 12, 39]:                           # NS, CNAME, PTR
        rdata, junk = get_domainname(pkt, offset)            # DNAME
        rdata = pdomainname(rdata)
    elif rrtype == 6:                                        # SOA
        rdata = decode_soa_rdata(pkt, offset, rdlen)
    elif rrtype == 15:                                       # MX
        mx_pref, = struct.unpack('!H', pkt[offset:offset+2])
        rdata, junk = get_domainname(pkt, offset+2)
        rdata = "%d %s" % (mx_pref, pdomainname(rdata))
    elif rrtype in [16, 99]:                                 # TXT, SPF
        rdata = decode_txt_rdata(rdata, rdlen)
    elif rrtype == 28:                                       # AAAA
        rdata = socket.inet_ntop(socket.AF_INET6, rdata)
    elif rrtype == 33:                                       # SRV
        rdata = decode_srv_rdata(pkt, offset)
    elif rrtype == 35:                                       # NAPTR
        rdata = decode_naptr_rdata(pkt, offset, rdlen)
    elif rrtype in [43, 32769]:                              # DS, DLV
        rdata = decode_ds_rdata(pkt, offset, rdlen)
    elif rrtype == 44:                                       # SSHFP
        rdata = decode_sshfp_rdata(pkt, offset, rdlen)
    elif rrtype == 45:                                       # IPSECKEY
        rdata = decode_ipseckey_rdata(pkt, offset, rdlen)
    elif rrtype in [46, 24]:                                 # RRSIG, SIG
        rdata = decode_rrsig_rdata(pkt, offset, rdlen)
    elif rrtype == 47:                                       # NSEC
        rdata = decode_nsec_rdata(pkt, offset, rdlen)
    elif rrtype in [48, 25]:                                 # DNSKEY, KEY
        rdata = decode_dnskey_rdata(pkt, offset, rdlen)
    elif rrtype == 50:                                       # NSEC3
        rdata = decode_nsec3_rdata(pkt, offset, rdlen)
    elif rrtype == 51:                                       # NSEC3PARAM
        rdata = decode_nsec3param_rdata(pkt, offset, rdlen)
    elif rrtype == 250:                                      # TSIG
        tsig_name = pdomainname(domainname)
        rdata = tsig.decode_tsig_rdata(pkt, offset, rdlen,
                                       tsig_name, orig_offset)
    else:                                                    # use RFC 3597
        rdata = generic_rdata_encoding(rdata, rdlen)
    offset += rdlen
    return (domainname, rrtype, rrclass, ttl, rdata, offset)


def decode_nsec_rr(pkt, offset):
    """ Decode an NSEC resource record; used by zonewalk() routine"""
    
    domainname, offset = get_domainname(pkt, offset)
    rrtype, rrclass, ttl, rdlen = \
            struct.unpack("!HHIH", pkt[offset:offset+10])
    if rrtype != 47:
        raise ErrorMessage("encountered RR type %s, expecting NSEC" % rrtype)
    
    offset += 10
    rdata = pkt[offset:offset+rdlen]

    end_rdata = offset + rdlen
    d, offset = get_domainname(pkt, offset)
    nextrr = pdomainname(d)
    type_bitmap = pkt[offset:end_rdata]
    p = type_bitmap
    rrtypelist = []
    while p:
        windownum, winlen = struct.unpack('BB', p[0:2])
        bitmap = p[2:2+winlen]
        rrtypelist += decode_typebitmap(windownum, bitmap)
        p = p[2+winlen:]
    offset += rdlen
    return (domainname, rrtype, rrclass, ttl, nextrr, rrtypelist, offset)


def print_answer_rr(server_addr, port, family, qname, qtype, options):
    """Only print the answer RRs; used by zonewalk() routine"""
    id = mk_id()
    tc = 0
    qtype_val = qt.get_val(qtype)
    options["use_edns0"] = True
    options["dnssec_ok"] = False
    request = mk_request(qname, qtype_val, 1, id, options)
    (responsepkt, responder_addr) = \
                  send_request_udp(request, server_addr, port, family,
                                   ITIMEOUT, RETRIES)
    if not responsepkt:
        raise ErrorMessage("No response from server")
    answerid, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, \
              qdcount, ancount, nscount, arcount = \
              decode_header(responsepkt, id)

    if rcode != 0:
        raise ErrorMessage("got rcode=%d(%s)" %
                           (rcode, rc.get_name(rcode)))
        
    r = responsepkt
    offset = 12                     # skip over DNS header

    for i in range(qdcount):
        domainname, rrtype, rrclass, offset = decode_question(r, offset)

    if ancount == 0:
        dprint("Warning: no answer RRs found for %s,%s" % \
              (qname, qt.get_name(qtype_val)))
        return

    for i in range(ancount):
        domainname, rrtype, rrclass, ttl, rdata, offset = \
                    decode_rr(r, offset, False)
        print "%s\t%d\t%s\t%s\t%s" % \
              (pdomainname(domainname), ttl,
               qc.get_name(rrclass), qt.get_name(rrtype), rdata)
    return
    

def zonewalk(server_addr, port, family, qname, options):
    """perform zone walk of zone containing the specified qname"""
    print ";;\n;; Performing walk of zone containing %s\n;;" % qname
    start_qname = qname
    nsec_count = 0
    while True:
        id = mk_id()
        tc = 0
        options["use_edns0"] = True
        options["dnssec_ok"] = False
        request = mk_request(qname, 47, 1, id, options)
        dprint("Querying NSEC for %s .." % qname)
        (responsepkt, responder_addr) = \
                      send_request_udp(request, server_addr, port, family,
                                       ITIMEOUT, RETRIES)
        if not responsepkt:
            raise ErrorMessage("No response from server")
        answerid, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, \
                  qdcount, ancount, nscount, arcount = \
                  decode_header(responsepkt, id)

        if rcode != 0:
            raise ErrorMessage("got rcode=%d(%s), querying %s, NSEC" %
                               (rcode, rc.get_name(rcode), qname))
        
        if ancount == 0:
            raise ErrorMessage("unable to find NSEC record at %s" % qname)
        elif ancount != 1:
            raise ErrorMessage("found %d answers, expecting 1 for %s NSEC" %
                               (ancount, qname))

        r = responsepkt
        offset = 12                     # skip over DNS header

        for i in range(qdcount):        # skip over question section
            domainname, rrtype, rrclass, offset = decode_question(r, offset)

        domainname, rrtype, rrclass, ttl, nextrr, rrtypelist, offset = \
                    decode_nsec_rr(r, offset)
        rrname = pdomainname(domainname)
        nsec_count += 1
        if (nsec_count !=1) and \
           (domain_name_match(rrname, nextrr) or
            domain_name_match(rrname, start_qname)):
            break

        for rrtype in rrtypelist:
            dprint("Querying RR %s %s .." % (qname, rrtype))
            print_answer_rr(server_addr, port, family, qname, rrtype, options)
        qname = nextrr
        time.sleep(0.4)                          # be nice
    return


if __name__ == '__main__':

    sys.excepthook = excepthook

    tsig = Tsig()                          # instantiate Tsig object
    try:
        qname, qtype, qclass = parse_args(sys.argv[1:])
        qtype_val = qt.get_val(qtype)
        qclass_val = qc.get_val(qclass)
    except (ValueError, IndexError, KeyError), diag:
        raise UsageError("Incorrect program usage! %s" % diag)
    
    if options["do_0x20"]:
        qname = randomize_case(qname)
        
    try:
        server_addr, port, family, socktype = \
                     get_socketparams(options["server"], options["port"],
                                      options["af"], socket.SOCK_DGRAM)
    except socket.gaierror, diag:
        raise ErrorMessage("bad server: %s (%s)" % (options["server"], diag))
        
    if options["do_zonewalk"]:
        zonewalk(server_addr, port, family, qname, options)
        sys.exit(0)
        
    id = mk_id()
    tc = 0
    request = mk_request(qname, qtype_val, qclass_val, id, options)

    if qtype == "AXFR":
        response, resplen = do_axfr(request, server_addr, port, family)
        decode_axfr(response, resplen)
        sys.exit(0)

    # the rest is for non AXFR queries ..

    if not options["use_tcp"]:
        t1 = time.time()
        (responsepkt, responder_addr) = \
                      send_request_udp(request, server_addr, port, family,
                                       ITIMEOUT, RETRIES)
        t2 = time.time()
        if not responsepkt:
            raise ErrorMessage("No response from server")
        answerid, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, \
                  qdcount, ancount, nscount, arcount = \
                  decode_header(responsepkt, id)
        if not tc:
            print ";; UDP response from %s, %d bytes, in %.3f sec" % \
                  (responder_addr, len(responsepkt), (t2-t1))
            if server_addr != "0.0.0.0" and responder_addr[0] != server_addr:
                print "WARNING: Response from unexpected address %s" % \
                      responder_addr[0]

    if options["use_tcp"] or tc:
        if tc:
            print ";; UDP Response was truncated. Retrying using TCP ..."
        t1 = time.time()
        responsepkt = send_request_tcp(request, server_addr, port, family)
        t2 = time.time()
        print ";; TCP response from %s, %d bytes, in %.3f sec" % \
              ( (server_addr, port), len(responsepkt)-2, (t2-t1))
        responsepkt = responsepkt[2:]           # ignore 2-byte length
        answerid, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, \
                  qdcount, ancount, nscount, arcount = \
                  decode_header(responsepkt, id)

    if options["do_0x20"]:
        print ";; 0x20-hack qname: %s" % qname
    print ";; rcode=%d(%s), id=%d" % (rcode, rc.get_name(rcode), answerid)
    print ";; qr=%d opcode=%d aa=%d tc=%d rd=%d ra=%d z=%d ad=%d cd=%d" % \
          (qr, opcode, aa, tc, rd, ra, z, ad, cd)
    print ";; question=%d, answer=%d, authority=%d, additional=%d\n" % \
          (qdcount, ancount, nscount, arcount)
    
    r = responsepkt
    offset = 12                     # skip over DNS header

    print ";; question section (%d records)" % qdcount
    for i in range(qdcount):
        domainname, rrtype, rrclass, offset = decode_question(r, offset)
        answer_qname = pdomainname(domainname)
        print "%s\t%s\t%s" % (answer_qname,
                              qc.get_name(rrclass), qt.get_name(rrtype))
    print

    ## make sure answered question matches posed question.
    if (not domain_name_match(answer_qname, qname, options["do_0x20"])) \
       or (qtype_val != rrtype) or (qclass_val != rrclass):
        print "\n*** WARNING: Answer didn't match question!\n"

    for section, rrcount in \
        [("answer", ancount),  ("authority", nscount), ("additional", arcount)]:
        if rrcount == 0: continue
        print ";; %s section (%d records)" % (section, rrcount)
        for i in range(rrcount):
            domainname, rrtype, rrclass, ttl, rdata, offset = \
                        decode_rr(r, offset, options["hexrdata"])
            if section == "additional" and rrtype == 41:        # OPT RR
                print_optrr(rrclass, ttl, rdata)
            else:
                print "%s\t%d\t%s\t%s\t%s" % \
                      (pdomainname(domainname), ttl,
                       qc.get_name(rrclass), qt.get_name(rrtype), rdata)
        print

    dprint("Compression pointer dereferences=%d" % count_compression)

    sys.exit(0)
