"""
Query routines.

"""

import socket
import select
import struct
import ssl

from .util import sendSocket, recvSocket, is_multicast
from .common import options, ErrorMessage, dprint, TIMEOUT_MAX, Counter, BUFSIZE
from .dnsparam import rc
from .dnsmsg import DNSresponse
from .tls import get_ssl_context, get_ssl_connection


def addresses_match(querier, responder):
    """check that responder address and port match query"""
    if responder[0:2] == querier:
        return True
    if querier[0] == '0.0.0.0' and responder[0] == '127.0.0.1':
        return True
    if querier[0] == '::' and responder[0] == '::1':
        return True
    return False


def send_request_udp(pkt, host, port, family, itimeout, retries):
    """Send the request via UDP, with retries using exponential backoff"""

    response, responder = b"", ("", 0)
    s = socket.socket(family, socket.SOCK_DGRAM)
    if options["srcip"]:
        s.bind((options["srcip"], 0))
        if is_multicast(host) and (host.find('.') != -1):
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, \
                         socket.inet_aton(options["srcip"]))
    timeout = itimeout
    while retries > 0:
        s.settimeout(timeout)
        try:
            s.sendto(pkt, (host, port))
            while True:
                response, responder = s.recvfrom(BUFSIZE)
                if addresses_match((host, port), responder):
                    break
                response = b""
                dprint(f"UDP response from unexpected source {responder}")
            break
        except socket.timeout:
            timeout = timeout * 2
            dprint("Request timed out with no answer")
        retries -= 1
    s.close()
    return (response, responder)


def send_request_tcp(pkt, host, port, family):
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
            ready_r, _, _ = select.select([s], [], [])
        except select.error as e:
            raise ErrorMessage("fatal error from select(): %s" % e)
        if ready_r and (s in ready_r):
            lbytes = recvSocket(s, 2)
            if len(lbytes) != 2:
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
        if len(lbytes) != 2:
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
            if len(lbytes) != 2:
                raise ErrorMessage("recv() on socket failed.")
            msg_len, = struct.unpack('!H', lbytes)
            msg = recvSocket(s, msg_len)
            msgsizes.addvalue(msg_len)
            response = DNSresponse(family, query, msg, 0, checkid=False)
            if response.rcode != 0:
                raise ErrorMessage("AXFR rcode %s" % rc.get_name(response.rcode))
            response.decode_sections(is_axfr=True)
            rrtotal += response.ancount

    except socket.timeout:
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
