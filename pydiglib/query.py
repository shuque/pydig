
import os, sys, errno, socket, select, struct, random

from .options import options
from .util import *
from .common import *
from .dnsparam import *
from .dnsmsg import *


def mk_id():
    """Return a 16-bit ID number to be used by the DNS request packet"""
    if options["msgid"]:
        return options["msgid"]
    else:
        return random.randint(1,65535)


def mk_optrr(edns_version, udp_payload, dnssec_ok=False, cookie=False):
    """Create EDNS0 OPT RR; see RFC 2671"""
    rdata     = ""
    rrname    = '\x00'                                   # empty domain
    rrtype    = struct.pack('!H', qt.get_val("OPT"))     # OPT type code
    rrclass = struct.pack('!H', udp_payload)             # udp payload
    if dnssec_ok: z = 0x8000
    else:         z = 0x0
    ttl   = struct.pack('!BBH', 0, edns_version, z)      # extended rcode
    if cookie:
        optcode = struct.pack('!H', 10)
        if cookie == True:
            optdata = open("/dev/urandom").read(8)
            optlen = struct.pack('!H', 8)
        else:
            try:
                optdata = h2bin(cookie)
            except:
                raise ErrorMessage("Malformed cookie supplied: %s" % cookie)
            optlen = struct.pack('!H', len(optdata))
        rdata = optcode + optlen + optdata
    rdlen = struct.pack('!H', len(rdata))
    return "%s%s%s%s%s%s" % (rrname, rrtype, rrclass, ttl, rdlen, rdata)


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

    if options["use_edns0"]:
        arcount = struct.pack('!H', 1)
        additional = mk_optrr(0, EDNS0_UDPSIZE, 
                              dnssec_ok=options["dnssec_ok"],
                              cookie=options["cookie"]);
    else:
        arcount = struct.pack('!H', 0)
        additional = ""

    flags = (qr << 15) + (opcode << 11) + (aa << 10) + (tc << 9) + \
            (rd << 8) + (ra << 7) + (z << 6) + (ad << 5) + (cd << 4) + rcode
    flags = struct.pack('!H', flags)

    wire_qname = txt2domainname(query.qname)          # wire format domainname

    question = "%s%s%s" % (wire_qname, struct.pack('!H', query.qtype),
                           struct.pack('!H', query.qclass))
        
    msg = "%s%s%s%s%s%s%s%s" % \
          (packed_id, flags, qdcount, ancount, nscount, arcount,
           question, additional)

    if options["do_tsig"]:                      # sign message with TSIG
        tsig = options["tsig"]
        tsig_rr = tsig.mk_request_tsig(sent_id, msg)
        arcount, = struct.unpack('!H', arcount)
        arcount = struct.pack('!H', arcount+1)
        additional = "%s%s" % (additional, tsig_rr)
        msg = "%s%s%s%s%s%s%s%s" % \
              (packed_id, flags, qdcount, ancount, nscount, arcount,
               question, additional)

    return msg


def send_request_udp(pkt, host, port, family, itimeout, retries):
    """Send the request via UDP, with retries using exponential backoff"""
    gotresponse = False
    responsepkt, responder_addr = "", ("", 0)
    s = socket.socket(family, socket.SOCK_DGRAM)
    if options["srcip"]:
        s.bind((options["srcip"], 0))
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
    if options["srcip"]:
        s.bind((options["srcip"], 0))
    response = ""
    try:
        s.connect((host, port))
        if not sendSocket(s, pkt):
            raise Exception, "send() on socket failed."
        lbytes = recvSocket(s, 2)
        if (len(lbytes) != 2):
            raise ErrorMessage("recv() on socket failed.")
        resp_len, = struct.unpack('!H', lbytes)
        response = recvSocket(s, resp_len)
    except socket.error, diag:
        s.close()
        raise ErrorMessage("tcp socket error: %s" % diag)
    s.close()
    return response


def send_request_tcp2(pkt, host, port, family):
    """Send the request packet via TCP, using select"""

    pkt = struct.pack("!H", len(pkt)) + pkt       # prepend 2-byte length
    s = socket.socket(family, socket.SOCK_STREAM)
    if options["srcip"]:
        s.bind((options["srcip"], 0))
    #s.setblocking(0)
    response = ""

    try:
        s.connect((host, port))
        if not sendSocket(s, pkt):
            raise Exception, "send() on socket failed."
    except socket.error, e:
        s.close()
        raise ErrorMessage("tcp socket send error: %s" % e)

    while True:
        try:
            (ready_r, ready_w, ready_e) = select.select([s], [], [])
        except select.error, e:
            if e.args[0] == errno.EINTR:
                continue
            else:
                raise e
        if ready_r and (s in ready_r):
            lbytes = recvSocket(s, 2)
            if (len(lbytes) != 2):
                raise ErrorMessage("recv() on socket failed.")
            resp_len, = struct.unpack('!H', lbytes)
            response = recvSocket(s, resp_len)
            break

    s.close()
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
            raise Exception, "send() on socket failed."
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

    except socket.timeout, diag:
        pass
    except socket.error, diag:
        s.close()
        raise ErrorMessage("tcp socket error: %s" % diag)
    s.close()

    print "\n;; Total RRs transferred: %d, Total messages: %d" % \
        (rrtotal, msgsizes.count)
    print ";; Message sizes: %d max, %d min, %d average" % \
          (msgsizes.max, msgsizes.min, msgsizes.average())
    if options["do_tsig"]:
        tsig = options["tsig"]
        print ";; TSIG records: %d, success: %d, failure: %d" % \
              (tsig.tsig_total, tsig.verify_success, tsig.verify_failure)

    return

