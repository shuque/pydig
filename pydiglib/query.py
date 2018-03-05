import os, sys, errno, socket, select, struct, random, math

from .options import options
from .util import *
from .common import *
from .dnsparam import *
from .dnsmsg import *
from .tls import *


def mk_id():
    """Return a 16-bit ID number to be used by the DNS request packet"""
    if options["msgid"]:
        return options["msgid"]
    else:
        return random.randint(1,65535)


def mk_option_nsid():
    """Construct EDNS NSID option"""
    optcode = struct.pack('!H', 3)
    optlen = struct.pack('!H', 0)
    return optcode + optlen


def mk_option_expire():
    """Construct EDNS Expire option"""
    optcode = struct.pack('!H', 9)
    optlen = struct.pack('!H', 0)
    return optcode + optlen

def mk_option_padding(headerlen):
    """" Construct EDNS Padding option"""
    optcode = struct.pack('!H', 12)
    optdata=""
    alldata=""
    padlen = 0
    if (headerlen % 64) >= 1:
       padlen = (64 - headerlen) % 64
    else:
       padlen = 0
    for i in range (0,padlen):
       optdata+=struct.pack('!H', 0)
    optlen = struct.pack('!H', len(optdata))
    alldata += optcode + optlen + optdata
    return alldata

def mk_option_client_subnet():
    """construct EDNS client subnet option"""
    prefix_addr, prefix_len = options["subnet"].split("/")
    prefix_len = int(prefix_len)
    addr_octets = int(math.ceil(prefix_len/8.0))
    if prefix_addr.find('.') != -1:                    # IPv4
        af = struct.pack('!H', 1)
        address = socket.inet_pton(socket.AF_INET, prefix_addr)[0:addr_octets]
    elif prefix_addr.find(':') != -1:                  # IPv6
        af = struct.pack('!H', 2)
        address = socket.inet_pton(socket.AF_INET6, prefix_addr)[0:addr_octets]
    else:
        raise ErrorMessage("Invalid client subnet address: %s" % prefix_addr)
    src_prefix_len = struct.pack('B', prefix_len)
    scope_prefix_len = b'\x00'
    optcode = struct.pack('!H', 8)
    optdata = af + src_prefix_len + scope_prefix_len + address
    optlen = struct.pack('!H', len(optdata))
    return optcode + optlen + optdata


def mk_option_cookie():
    """Construct EDNS cookie option"""
    optcode = struct.pack('!H', 10)
    if options["cookie"] == True:
        optdata = os.urandom(8)
        optlen = struct.pack('!H', 8)
    else:
        try:
            optdata = h2bin(options["cookie"])
        except:
            raise ErrorMessage("Malformed cookie: %s" % options["cookie"])
        optlen = struct.pack('!H', len(optdata))
    return optcode + optlen + optdata


def mk_option_chainquery():
    """Construct EDNS chain query option"""
    optcode = struct.pack('!H', 13)
    if options["chainquery"] == True:
        optdata = b'\x00'
    else:
        optdata = txt2domainname(options["chainquery"])
    optlen = struct.pack('!H', len(optdata))
    return optcode + optlen + optdata


def mk_option_generic():
    """Construct generic EDNS options"""
    alldata = ""
    for (n, s) in options["ednsopt"]:
        optcode = struct.pack('!H', n)
        optdata = h2bin(s)
        optlen = struct.pack('!H', len(optdata))
        alldata += optcode + optlen + optdata
    return alldata


def mk_optrr(edns_version, udp_payload, flags=0, dnssec_ok=False):
    """Create EDNS0 OPT RR; see RFC 2671"""
    headerlen = 0
    rdata     = b""
    rrname    = b'\x00'                                   # empty domain
    rrtype    = struct.pack('!H', qt.get_val("OPT"))     # OPT type code
    rrclass = struct.pack('!H', udp_payload)             # udp payload
    headerlen += len(rdata+rrname+rrtype+rrclass)
    if flags != 0: z = flags
    elif dnssec_ok: z = 0x8000
    else:         z = 0x0
    ttl   = struct.pack('!BBH', 0, edns_version, z)      # ercode, ver, flags
    headerlen += len(ttl)
    if options['nsid']:
        rdata += mk_option_nsid()
	headerlen += len(rdata)
    if options['expire']:
        rdata += mk_option_expire()
        headerlen += len(rdata)
    if options["cookie"]:
        rdata += mk_option_cookie()
        headerlen += len(rdata)
    if options["subnet"]:
        rdata += mk_option_client_subnet()
        headerlen += len(rdata)
    if options["chainquery"]:
        rdata += mk_option_chainquery()
        headerlen += len(rdata)
    if options["padding"]:
        rdata += mk_option_padding(headerlen)
    if options["ednsopt"]:
        rdata += mk_option_generic()
        headerlen += len(rdata)
    rdlen = struct.pack('!H', len(rdata))
    return (rrname + rrtype + rrclass + ttl + rdlen + rdata)


def mk_request(query, sent_id, options):
    """Construct DNS query packet, given various parameters"""
    packed_id = struct.pack('!H', sent_id)
    qr = 0                                      # query/response
    opcode = 0                                  # standard query
    aa = options["aa"]                          # authoritative answer
    tc = 0                                      # truncated response
    rd = options["rd"]                          # recursion desired
    ra = 0                                      # recursion available
    z = 0                                       # reserved
    ad = options["ad"]                          # authenticated data
    cd = options["cd"]                          # checking disabled
    rcode = 0                                   # response code
    qdcount = struct.pack('!H', 1)              # 1 question
    ancount = struct.pack('!H', 0)              # 0 answer
    nscount = struct.pack('!H', 0)              # 0 authority

    if options["use_edns"]:
        arcount = struct.pack('!H', 1)
        additional = mk_optrr(options["edns_version"],
                              options["bufsize"],
                              flags=options["edns_flags"],
                              dnssec_ok=options["dnssec_ok"])
    else:
        arcount = struct.pack('!H', 0)
        additional = b""

    flags = (qr << 15) + (opcode << 11) + (aa << 10) + (tc << 9) + \
            (rd << 8) + (ra << 7) + (z << 6) + (ad << 5) + (cd << 4) + rcode
    flags = struct.pack('!H', flags)

    wire_qname = txt2domainname(query.qname)          # wire format domainname

    question = wire_qname + struct.pack('!H', query.qtype) + struct.pack('!H', query.qclass)
        
    msg = packed_id + flags + qdcount + ancount + nscount + arcount + \
          question + additional

    if options["do_tsig"]:                      # sign message with TSIG
        tsig = options["tsig"]
        tsig_rr = tsig.mk_request_tsig(sent_id, msg)
        arcount, = struct.unpack('!H', arcount)
        arcount = struct.pack('!H', arcount+1)
        additional += tsig_rr
        msg = packed_id + flags + qdcount + ancount + nscount + arcount + \
              question + additional

    return msg


def send_request_udp(pkt, host, port, family, itimeout, retries):
    """Send the request via UDP, with retries using exponential backoff"""
    gotresponse = False
    responsepkt, responder_addr = b"", ("", 0)
    s = socket.socket(family, socket.SOCK_DGRAM)
    if options["srcip"]:
        s.bind((options["srcip"], 0))
        if is_multicast(host) and (host.find('.') != -1):
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, \
                         socket.inet_aton(options["srcip"]))
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

    pkt = struct.pack("!H", len(pkt)) + pkt       # prepend 2-byte length
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT_MAX)
    if options["srcip"]:
        s.bind((options["srcip"], 0))
    response = b""
    try:
        s.connect((host, port))
        if not sendSocket(s, pkt):
            raise ErrorMessage("send() on socket failed.")
        lbytes = recvSocket(s, 2)
        if (len(lbytes) != 2):
            raise ErrorMessage("recv() on socket failed.")
        resp_len, = struct.unpack('!H', lbytes)
        response = recvSocket(s, resp_len)
    except socket.error as e:
        s.close()
        raise ErrorMessage("tcp socket error: %s" % e)
    s.close()
    return response


def send_request_tcp2(pkt, host, port, family):
    """Send the request packet via TCP, using select"""

    pkt = struct.pack("!H", len(pkt)) + pkt       # prepend 2-byte length
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT_MAX)
    if options["srcip"]:
        s.bind((options["srcip"], 0))
    #s.setblocking(0)
    response = b""

    try:
        s.connect((host, port))
        if not sendSocket(s, pkt):
            raise ErrorMessage("send() on socket failed.")
    except socket.error as e:
        s.close()
        raise ErrorMessage("tcp socket send error: %s" % e)

    while True:
        try:
            (ready_r, ready_w, ready_e) = select.select([s], [], [])
        except select.error as e:
            if e[0] == errno.EINTR:
                continue
            else:
                raise ErrorMessage("fatal error from select(): %s" % e)
        if ready_r and (s in ready_r):
            lbytes = recvSocket(s, 2)
            if (len(lbytes) != 2):
                raise ErrorMessage("recv() on socket failed.")
            resp_len, = struct.unpack('!H', lbytes)
            response = recvSocket(s, resp_len)
            break

    s.close()
    return response


def send_request_tls(pkt, host, port, family, hostname=None):
    """Send the request packet using DNS over TLS"""

    pkt = struct.pack("!H", len(pkt)) + pkt       # prepend 2-byte length
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT_MAX)
    if options["srcip"]:
        s.bind((options["srcip"], 0))
    response = ""

    ctx = get_ssl_context(options["tls_auth"], hostname)
    conn = get_ssl_connection(ctx, s, hostname)

    try:
        conn.connect((host, port))
    except socket.error as e:
        print("socket error: %s" % e)
    except ssl.SSLError as e:
        print("TLS error: %s" % e)
    else:
        if not sendSocket(conn, pkt):
            raise ErrorMessage("send() on socket failed.")
        lbytes = recvSocket(conn, 2)
        if (len(lbytes) != 2):
            raise ErrorMessage("recv() on socket failed.")
        resp_len, = struct.unpack('!H', lbytes)
        response = recvSocket(conn, resp_len)
    finally:
        conn.close()

    return response


def do_axfr(query, pkt, host, port, family):
    """AXFR uses TCP, and is answered by a sequence of response messages."""

    pkt = struct.pack("!H", len(pkt)) + pkt        # prepend 2-byte length
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(0.3)
    rrtotal = 0
    msgsizes = Counter()
    try:
        s.connect((host, port))
        if not sendSocket(s, pkt):
            raise ErrorMessage("send() on socket failed.")
        while True:
            lbytes = recvSocket(s, 2)
            if not lbytes:
                break
            elif (len(lbytes) != 2):
                raise ErrorMessage("recv() on socket failed.")
            msg_len, = struct.unpack('!H', lbytes)
            msg = recvSocket(s, msg_len)
            msgsizes.addvalue(msg_len)
            response = DNSresponse(family, query, pkt, msg, 0, checkid=False)
            if response.rcode != 0:
                raise ErrorMessage("AXFR rcode %s" % rc.get_name(response.rcode))
            response.decode_sections(is_axfr=True)
            rrtotal += response.ancount

    except socket.timeout as e:
        pass
    except socket.error as e:
        s.close()
        raise ErrorMessage("tcp socket error: %s" % e)
    s.close()

    print("\n;; Total RRs transferred: %d, Total messages: %d" %
          (rrtotal, msgsizes.count))
    print(";; Message sizes: %d max, %d min, %d average" %
          (msgsizes.max, msgsizes.min, msgsizes.average()))
    if options["do_tsig"]:
        tsig = options["tsig"]
        print(";; TSIG records: %d, success: %d, failure: %d" %
              (tsig.tsig_total, tsig.verify_success, tsig.verify_failure))

    return

