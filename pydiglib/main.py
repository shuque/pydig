
import os, sys, socket, time

from .common import *
from .options import options, parse_args
from .tsig import Tsig
from .util import *
from .dnsparam import *
from .dnsmsg import *
from .query import *
from .walk import zonewalk


def main(args):
    """ main function"""
    sys.excepthook = excepthook
    tsig = Tsig()                          # instantiate Tsig object

    try:
        qname, qtype, qclass = parse_args(args[1:])
        qtype_val = qt.get_val(qtype)
        qclass_val = qc.get_val(qclass)
    except (ValueError, IndexError, KeyError), diag:
        raise UsageError("Incorrect program usage.")

    if options["do_0x20"]:
        qname = randomize_case(qname)
    query = DNSquery(qname, qtype_val, qclass_val)
        
    try:
        server_addr, port, family, socktype = \
                     get_socketparams(options["server"], options["port"],
                                      options["af"], socket.SOCK_DGRAM)
    except socket.gaierror, diag:
        raise ErrorMessage("bad server: %s (%s)" % (options["server"], diag))
        
    if options["do_zonewalk"]:
        zonewalk(server_addr, port, family, qname, options)
        sys.exit(0)

    random_init()
    txid = mk_id()
    tc = 0
    requestpkt = mk_request(query, txid, options)
    size_query = len(requestpkt)

    if qtype == "AXFR":
        responses = do_axfr(query, requestpkt, server_addr, port, family)
        sys.exit(0)

    # the rest is for non AXFR queries ..

    response = None
    if not options["use_tcp"]:
        t1 = time.time()
        (responsepkt, responder_addr) = \
                      send_request_udp(requestpkt, server_addr, port, family,
                                       ITIMEOUT, RETRIES)
        t2 = time.time()
        size_response = len(responsepkt)
        if not responsepkt:
            raise ErrorMessage("No response from server")
        response = DNSresponse(family, query, requestpkt, responsepkt, txid)
        if not response.tc:
            print ";; UDP response from %s, %d bytes, in %.3f sec" % \
                  (responder_addr, size_response, (t2-t1))
            if server_addr != "0.0.0.0" and responder_addr[0] != server_addr:
                print "WARNING: Response from unexpected address %s" % \
                      responder_addr[0]

    if options["use_tcp"] or (response and response.tc):
        if (response and response.tc):
            print ";; UDP Response was truncated. Retrying using TCP ..."
        t1 = time.time()
        responsepkt = send_request_tcp2(requestpkt, server_addr, port, family)
        t2 = time.time()
        size_response = len(responsepkt)
        print ";; TCP response from %s, %d bytes, in %.3f sec" % \
              ( (server_addr, port), size_response, (t2-t1))
        response = DNSresponse(family, query, requestpkt, responsepkt, txid)

    response.print_preamble(options)
    response.decode_sections()
    dprint(";; Compression pointer dereferences=%d" % count_compression)

    return response.rcode
