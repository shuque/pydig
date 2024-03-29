"""
main function.

"""

import sys
import socket
import time

from .common import options, excepthook, dprint, Stats, ErrorMessage, UsageError, ITIMEOUT, RETRIES
from .options import parse_args
from .util import random_init, get_socketparams
from .dnsparam import qc, qt
from .dnsmsg import DNSquery, DNSresponse
from .query import send_request_udp, send_request_tcp, send_request_tls, do_axfr
from .https import send_request_https
from .walk import zonewalk


def main(args):

    """ main function"""

    sys.excepthook = excepthook
    random_init()

    qname, qtype, qclass = parse_args(args[1:])

    try:
        qtype_val = qt.get_val(qtype)
    except KeyError:
        raise UsageError("ERROR: invalid query type: {}\n".format(qtype))

    try:
        qclass_val = qc.get_val(qclass)
    except KeyError:
        raise UsageError("ERROR: invalid query class: {}\n".format(qclass))

    query = DNSquery(qname, qtype_val, qclass_val)

    try:
        server_addr, port, family, _ = \
                     get_socketparams(options["server"], options["port"],
                                      options["af"], socket.SOCK_DGRAM)
    except socket.gaierror as e:
        raise ErrorMessage("bad server: %s (%s)" % (options["server"], e))

    if options["do_zonewalk"]:
        zonewalk(server_addr, port, family, qname, options)
        sys.exit(0)

    request = query.get_message()

    if (qtype == "AXFR") or (qtype == "IXFR" and options["use_tcp"]):
        do_axfr(query, request, server_addr, port, family)
        sys.exit(0)

    # the rest is for non AXFR queries ..

    response = None

    if options["https"]:
        t1 = time.time()
        responsepkt = send_request_https(request, options["https_url"])
        t2 = time.time()
        if responsepkt:
            response = DNSresponse(family, query, responsepkt)
            print(";; HTTPS response from %s, %d bytes, in %.3f sec" %
                  (options["https_url"], response.msglen, (t2-t1)))
        else:
            print(";; HTTPS response failure from %s" % options["https_url"])
            return 2

    elif options["tls"]:
        t1 = time.time()
        responsepkt = send_request_tls(request, server_addr,
                                       options["tls_port"], family,
                                       hostname=options["tls_hostname"])
        t2 = time.time()
        if responsepkt:
            response = DNSresponse(family, query, responsepkt)
            print(";; TLS response from %s, %d bytes, in %.3f sec" %
                  ((server_addr, options["tls_port"]), response.msglen, (t2-t1)))
        else:
            print(";; TLS response failure from %s, %d" %
                  (server_addr, options["tls_port"]))
            if not options["tls_fallback"]:
                return 2

    elif not options["use_tcp"]:
        t1 = time.time()
        (responsepkt, responder_addr) = \
                      send_request_udp(request, server_addr, port, family,
                                       ITIMEOUT, RETRIES)
        t2 = time.time()
        if not responsepkt:
            raise ErrorMessage("No response from server")
        response = DNSresponse(family, query, responsepkt)
        if not response.tc:
            print(";; UDP response from %s, %d bytes, in %.3f sec" %
                  (responder_addr, response.msglen, (t2-t1)))

    if options["use_tcp"] or (response and response.tc) \
       or (options["tls"] and options["tls_fallback"] and not response):
        if response and response.tc:
            if options["ignore"]:
                print(";; UDP Response was truncated.")
            else:
                print(";; UDP Response was truncated. Retrying using TCP ...")
        if options["tls"] and options["tls_fallback"] and not response:
            print(";; TLS fallback to TCP ...")
        if not options["ignore"]:
            t1 = time.time()
            responsepkt = send_request_tcp(request, server_addr, port, family)
            t2 = time.time()
            response = DNSresponse(family, query, responsepkt)
            print(";; TCP response from %s, %d bytes, in %.3f sec" %
                  ((server_addr, port), response.msglen, (t2-t1)))

    response.print_all()
    dprint("Compression pointer dereferences=%d" % Stats.compression_cnt)

    return response.rcode
