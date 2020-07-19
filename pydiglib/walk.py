"""
NSEC Zone Walking routine.
"""

import struct
import time

from .common import dprint, ErrorMessage, ITIMEOUT, RETRIES
from .dnsparam import qt, qc, rc
from .name import name_from_wire_message, name_from_text, name_match
from .dnsmsg import DNSquery, DNSresponse
from .query import send_request_udp
from .rdata import decode_rr, decode_typebitmap


def print_answer_rr(server_addr, port, family, qname, qtype, options):
    """
    Only print the answer RRs; used by zonewalk() routine.
    """

    qtype_val = qt.get_val(qtype)
    options["use_edns"] = True
    options["dnssec_ok"] = False
    query = DNSquery(qname, qtype_val, 1)
    requestpkt = query.get_message()
    responsepkt, _ = \
        send_request_udp(requestpkt, server_addr, port, family,
                         ITIMEOUT, RETRIES)
    if not responsepkt:
        raise ErrorMessage("No response from server")
    response = DNSresponse(family, query, responsepkt)

    if response.rcode != 0:
        raise ErrorMessage("got rcode=%d(%s)" %
                           (response.rcode, rc.get_name(response.rcode)))

    r = responsepkt
    offset = 12                     # skip over DNS header

    for _ in range(response.qdcount):
        _, rrtype, rrclass, offset = response.decode_question(offset)

    if response.ancount == 0:
        dprint("Warning: no answer RRs found for %s,%s" % \
              (qname, qt.get_name(qtype_val)))
        return

    for _ in range(response.ancount):
        rrname, rrtype, rrclass, ttl, rdata, offset = \
                    decode_rr(r, offset, False)
        print("%s\t%d\t%s\t%s\t%s" %
              (rrname.text(), ttl,
               qc.get_name(rrclass), qt.get_name(rrtype), rdata))
    return


def decode_nsec_rr(pkt, offset):
    """ Decode an NSEC resource record; used by zonewalk() routine"""

    domainname, offset = name_from_wire_message(pkt, offset)
    rrtype, rrclass, ttl, rdlen = \
            struct.unpack("!HHIH", pkt[offset:offset+10])
    if rrtype != 47:
        raise ErrorMessage("encountered RR type %s, expecting NSEC" % rrtype)

    offset += 10
    end_rdata = offset + rdlen
    d, offset = name_from_wire_message(pkt, offset)
    nextrr = d
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


def zonewalk(server_addr, port, family, qname, options):
    """
    Perform zone walk of NSEC zone containing the specified qname.
    """

    print(";;\n;; Performing walk of zone containing %s\n;;" % qname)
    start_qname = name_from_text(qname)
    nsec_count = 0
    options["use_edns"] = True
    options["dnssec_ok"] = False
    while True:
        query = DNSquery(qname, 47, 1)
        requestpkt = query.get_message()
        dprint("Querying NSEC for %s .." % query.qname)
        responsepkt, _ = \
            send_request_udp(requestpkt, server_addr, port, family,
                             ITIMEOUT, RETRIES)
        if not responsepkt:
            raise ErrorMessage("No response from server")
        response = DNSresponse(family, query, responsepkt)

        if response.rcode != 0:
            raise ErrorMessage("got rcode=%d(%s), querying %s, NSEC" %
                               (response.rcode, rc.get_name(response.rcode), qname))

        if response.ancount == 0:
            raise ErrorMessage("unable to find NSEC record at %s" % qname)
        elif response.ancount != 1:
            raise ErrorMessage("found %d answers, expecting 1 for %s NSEC" %
                               (response.ancount, qname))

        r = responsepkt
        offset = 12                     # skip over DNS header

        for _ in range(response.qdcount):        # skip over question section
            domainname, rrtype, _, offset = response.decode_question(offset)

        domainname, rrtype, _, _, nextrr, rrtypelist, offset = \
            decode_nsec_rr(r, offset)
        nsec_count += 1
        if (nsec_count != 1) and \
           (name_match(domainname, nextrr) or name_match(domainname, start_qname)):
            break

        for rrtype in rrtypelist:
            dprint("Querying RR %s %s .." % (qname, rrtype))
            print_answer_rr(server_addr, port, family, qname, rrtype, options)
        qname = nextrr.text()
        time.sleep(0.3)                          # be nice
    return
