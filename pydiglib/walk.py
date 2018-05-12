from .common import *
from .dnsparam import *
from .dnsmsg import *
from .name import *
from .query import *


def print_answer_rr(server_addr, port, family, qname, qtype, options):
    """Only print the answer RRs; used by zonewalk() routine"""
    qtype_val = qt.get_val(qtype)
    options["use_edns"] = True
    options["dnssec_ok"] = False
    query = DNSquery(qname, qtype_val, 1)
    requestpkt = query.get_message()
    (responsepkt, responder_addr) = \
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

    for i in range(response.qdcount):
        domainname, rrtype, rrclass, offset = response.decode_question(offset)

    if response.ancount == 0:
        dprint("Warning: no answer RRs found for %s,%s" % \
              (qname, qt.get_name(qtype_val)))
        return

    for i in range(response.ancount):
        rrname, rrtype, rrclass, ttl, rdata, offset = \
                    decode_rr(r, offset, False)
        print("%s\t%d\t%s\t%s\t%s" % 
              (rrname.text(), ttl,
               qc.get_name(rrclass), qt.get_name(rrtype), rdata))
    return
    

def zonewalk(server_addr, port, family, qname, options):
    """perform zone walk of zone containing the specified qname"""
    print(";;\n;; Performing walk of zone containing %s\n;;" % qname)
    start_qname = name_from_text(qname)
    nsec_count = 0
    options["use_edns"] = True
    options["dnssec_ok"] = False
    while True:
        query = DNSquery(qname, 47, 1)
        requestpkt = query.get_message()
        dprint("Querying NSEC for %s .." % query.qname)
        (responsepkt, responder_addr) = \
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
                               (ancount, qname))

        r = responsepkt
        offset = 12                     # skip over DNS header

        for i in range(response.qdcount):        # skip over question section
            domainname, rrtype, rrclass, offset = response.decode_question(offset)

        domainname, rrtype, rrclass, ttl, nextrr, rrtypelist, offset = \
                    decode_nsec_rr(r, offset)
        nsec_count += 1
        if (nsec_count !=1) and \
           (name_match(domainname, nextrr) or name_match(domainname, start_qname)):
            break

        for rrtype in rrtypelist:
            dprint("Querying RR %s %s .." % (qname, rrtype))
            print_answer_rr(server_addr, port, family, qname, rrtype, options)
        qname = nextrr.text()
        time.sleep(0.3)                          # be nice
    return

