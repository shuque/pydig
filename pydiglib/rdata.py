import socket
import struct
import time
import string
import base64
import math

from .options import options
from .common import *
from .dnsparam import *
from .name import *
from .edns import *
from .util import *
from .rr_svcb import RdataSVCB


def print_optrr(rcode, rrclass, ttl, rdata):
    """decode and print EDNS0 OPT pseudo RR; see RFC 2671"""
    packed_ttl = struct.pack('!I', ttl)
    ercode_hi, version, z = struct.unpack('!BBH', packed_ttl)
    ercode = (ercode_hi << 4) | rcode
    flags = []
    if z & 0x8000: flags.append("do")                  # DNSSEC OK bit
    print(";; OPT: edns_version=%d, udp_payload=%d, flags=%s, ercode=%d(%s)" %
          (version, rrclass, ' '.join(flags), ercode, rc.get_name(ercode)))
    blob = rdata
    while blob:
        ocode, olen = struct.unpack('!HH', blob[:4])
        odesc = edns_opt.get(ocode, "Unknown")
        print(";; OPT code=%d (%s), length=%d" % (ocode, odesc, olen))
        data_raw = blob[4:4+olen]
        data_out = hexdump(data_raw)
        if ocode == 3:                           # NSID
            human_readable_data = ''
            try:
                human_readable_data = data_raw.decode('ascii')
            except (TypeError, UnicodeDecodeError):
                pass
            if human_readable_data:
                data_out = '%s (%s)' % (data_out, human_readable_data)
        print(";; DATA: %s" % data_out)
        blob = blob[4+olen:]


def generic_rdata_encoding(rdata, rdlen):
    """return generic encoding of rdata for unknown types; see RFC 3597"""
    return "\# %d %s" % (rdlen, hexdump(rdata))

    
def decode_txt_rdata(rdata, rdlen):
    """decode TXT RR rdata into a string of quoted text strings,
    escaping any embedded double quotes"""
    txtstrings = []
    position = 0
    while position < rdlen:
        slen, = struct.unpack('B', rdata[position:position+1])
        s = rdata[position+1:position+1+slen]
        txtstring = '"{}"'.format(
            bytes2escapedstring(s, backslash_txt, printables_txt))
        txtstrings.append(txtstring)
        position += 1 + slen
    return ' '.join(txtstrings)


def decode_soa_rdata(pkt, offset, rdlen):
    """decode SOA rdata: mname, rname, serial, refresh, retry, expire, min"""
    d, offset = name_from_wire_message(pkt, offset)
    mname = d.text()
    d, offset = name_from_wire_message(pkt, offset)
    rname = d.text()
    serial, refresh, retry, expire, min = \
            struct.unpack("!IiiiI", pkt[offset:offset+20])
    return "%s %s %d %d %d %d %d" % \
           (mname, rname, serial, refresh, retry, expire, min)
    

def decode_srv_rdata(pkt, offset):
    """decode SRV rdata: priority (2), weight (2), port, target; RFC 2782"""
    priority, weight, port = struct.unpack("!HHH", pkt[offset:offset+6])
    d, offset = name_from_wire_message(pkt, offset+6)
    target = d.text()
    return "%d %d %d %s" % (priority, weight, port, target)


def decode_sshfp_rdata(pkt, offset, rdlen):
    """decode SSHFP rdata: alg, fp_type, fingerprint; see RFC 4255"""
    alg, fptype = struct.unpack('BB', pkt[offset:offset+2])
    fingerprint = hexdump(pkt[offset+2:offset+rdlen])
    if options['DEBUG']:
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
    d, _ = name_from_wire_message(pkt, position)
    replacement = d.text()
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
        d, position = name_from_wire_message(pkt, position)
        gw = d.text()
    if alg == 0:                               # no public key
        pubkey = ""
    else:
        pubkeylen = rdlen - (position - offset)
        pubkey = base64.standard_b64encode(pkt[position:position+pubkeylen]).decode('ascii')
    return "{} {} {} {} {}".format(prec, gwtype, alg, gw, pubkey)


def decode_tlsa_rdata(rdata):
    """decode TLSA rdata: usage(1) selector(1) mtype(1) cadata;
       see RFC 6698"""
    usage, selector, mtype = struct.unpack("BBB", rdata[0:3])
    cadata = hexdump(rdata[3:])
    return "%d %d %d %s" % (usage, selector, mtype, cadata)


def decode_openpgpkey_rdata(rdata):
    """decode OPENPGPKEY rdata: base64-string"""
    return "{}".format(base64.standard_b64encode(rdata).decode('ascii'))


def decode_dnskey_rdata(pkt, offset, rdlen):
    """decode DNSKEY rdata: flags, proto, alg, pubkey; see RFC 4034"""
    flags, proto, alg = struct.unpack('!HBB', pkt[offset:offset+4])
    pubkey = pkt[offset+4:offset+rdlen]
    if options['DEBUG']:
        zonekey = (flags >> 8) & 0x1;         # bit 7
        sepkey = flags & 0x1;                 # bit 15
        keytype = None
        if proto == 3:
            if zonekey and sepkey:
                keytype="KSK"
            elif zonekey:
                keytype="ZSK"
        if keytype: comments = "%s, " % keytype
        comments += "proto=%s, alg=%s" % \
                   (dnssec_proto[proto], dnssec_alg[alg])
        if alg in [5, 7, 8, 10]:              # RSA algorithms
            if pubkey[0] == '\x00':   # length field is 3 octets
                elen, = struct.unpack('!H', pubkey[1:3])
                exponent = packed2int(pubkey[1:1+elen])
                modulus_len = len(pubkey[1+elen:]) * 8
            else:                     # length field is 1 octet
                elen, = struct.unpack('B', pubkey[0:1])
                exponent = packed2int(pubkey[1:1+elen])
                modulus_len = len(pubkey[1+elen:]) * 8
            comments = comments + ", e=%d modulus_size=%d" % \
                       (exponent, modulus_len)
        elif alg in [3, 6]:                   # DSA algorithms
            # not decoded yet (not commonly seen?) - see RFC 2536
            pass
        elif alg in [13, 14]:                 # ECDSA algorithms
            # The pubkey is the concatenation of 2 curve points, so
            # for ECDSAP384, the size is 768 bits.
            comments = comments + ", size=%d" % (len(pubkey) * 8)
        result = "{} {} {} {} ; {}".format(
            flags, proto, alg,
            base64.standard_b64encode(pubkey).decode('ascii'), comments)
    else:
        result = "{} {} {} {}".format(
            flags, proto, alg,
            base64.standard_b64encode(pubkey).decode('ascii'))
    return result


def decode_ds_rdata(pkt, offset, rdlen):
    """decode DS rdata: keytag, alg, digesttype, digest; see RFC 4034"""
    keytag, alg, digesttype = struct.unpack('!HBB', pkt[offset:offset+4])
    digest = hexdump(pkt[offset+4:offset+rdlen])
    if options['DEBUG']:
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
    sig_exp_text = time.strftime("%Y%m%d%H%M%S", time.gmtime(sig_exp))
    sig_inc_text = time.strftime("%Y%m%d%H%M%S", time.gmtime(sig_inc))
    d, offset = name_from_wire_message(pkt, offset+18)
    signer_name = d.text()
    signature = pkt[offset:end_rdata]
    retval = "{} {} {} {} {} {} {} {} {}".format(
        qt.get_name(type_covered), alg, labels, orig_ttl,
        sig_exp_text, sig_inc_text, keytag, signer_name,
        base64.standard_b64encode(signature).decode('ascii'))
    if options['DEBUG']:
        sig_validity = "%.2fd" % ((sig_exp - sig_inc) / 86400.0)
        retval += " ; sigsize=%d, validity=%s" % \
            (len(signature) * 8, sig_validity)
    return retval


def decode_typebitmap(windownum, bitmap):
    """decode NSEC style type bitmap into list of RR types; see RFC 4034"""
    rrtypelist = []
    for (charpos, c) in enumerate(bitmap):
        for i in range(8):
            isset = (c << i) & 0x80
            if isset:
                bitpos = (256 * windownum) + (8 * charpos) + i
                rrtypelist.append(qt.get_name(bitpos))
    return rrtypelist


def decode_nsec_rdata(pkt, offset, rdlen):
    """decode NSEC rdata: nextrr, type-bitmap; see RFC 4034"""
    end_rdata = offset + rdlen
    d, offset = name_from_wire_message(pkt, offset)
    nextrr = d.text()
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
    salt = hexdump(pkt[offset+5:offset+5+saltlen])
    result = "%d %d %d %s" % (hashalg, flags, iterations, salt)
    return result


def decode_nsec3_rdata(pkt, offset, rdlen):
    """decode NSEC3 rdata; see RFC 5155 Section 3"""

    # Translation table for normal base32 to base32 with extended hex
    # alphabet used by NSEC3 (see RFC 4648, Section 7). This alphabet
    # has the property that encoded data maintains its sort order when
    # compared bitwise.
    b32_to_ext_hex = bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                                     b'0123456789ABCDEFGHIJKLMNOPQRSTUV')

    end_rdata = offset + rdlen
    hashalg, flags, iterations, saltlen = struct.unpack('!BBHB',
                                                        pkt[offset:offset+5])
    salt = hexdump(pkt[offset+5:offset+5+saltlen])
    offset += (5 + saltlen)
    hashlen, = struct.unpack('!B', pkt[offset:offset+1])
    offset += 1
    # hashed next owner name, base32 encoded with extended hex alphabet
    hashed_next_owner = base64.b32encode(pkt[offset:offset+hashlen])
    hashed_next_owner = hashed_next_owner.translate(b32_to_ext_hex).decode()
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


def decode_caa_rdata(rdata):
    """decode CAA rdata: TLSA rdata: flags(1), tag-length, tag, value;
       see RFC 6844"""
    flags, taglen = struct.unpack("BB", rdata[0:2])
    tag = rdata[2:2+taglen]
    value = rdata[2+taglen:]
    return "{} {} \"{}\"".format(flags, tag.decode(), value.decode())


def decode_rr(pkt, offset, hexrdata):
    """ Decode a resource record, given DNS packet and offset"""

    orig_offset = offset
    domainname, offset = name_from_wire_message(pkt, offset)
    rrtype, rrclass, ttl, rdlen = \
            struct.unpack("!HHIH", pkt[offset:offset+10])
    offset += 10
    rdata = pkt[offset:offset+rdlen]
    if hexrdata:
        rdata = hexdump(rdata)
    elif options["generic"]:
        rdata = generic_rdata_encoding(rdata, rdlen)
    elif rrtype == 1:                                        # A
        rdata = socket.inet_ntop(socket.AF_INET, rdata)
    elif rrtype in [2, 5, 12, 39]:                           # NS, CNAME, PTR
        rdata, _ = name_from_wire_message(pkt, offset)       # DNAME
        rdata = rdata.text()
    elif rrtype == 6:                                        # SOA
        rdata = decode_soa_rdata(pkt, offset, rdlen)
    elif rrtype == 15:                                       # MX
        mx_pref, = struct.unpack('!H', pkt[offset:offset+2])
        rdata, _ = name_from_wire_message(pkt, offset+2)
        rdata = "%d %s" % (mx_pref, rdata.text())
    elif rrtype in [16, 99]:                                 # TXT, SPF
        rdata = decode_txt_rdata(rdata, rdlen)
    elif rrtype == 28:                                       # AAAA
        rdata = socket.inet_ntop(socket.AF_INET6, rdata)
    elif rrtype == 33:                                       # SRV
        rdata = decode_srv_rdata(pkt, offset)
    elif rrtype == 41:                                       # OPT
        pass
    elif rrtype in [43, 59, 32769]:                          # [C]DS, DLV
        rdata = decode_ds_rdata(pkt, offset, rdlen)
    elif rrtype == 44:                                       # SSHFP
        rdata = decode_sshfp_rdata(pkt, offset, rdlen)
    elif rrtype == 45:                                       # IPSECKEY
        rdata = decode_ipseckey_rdata(pkt, offset, rdlen)
    elif rrtype in [46, 24]:                                 # RRSIG, SIG
        rdata = decode_rrsig_rdata(pkt, offset, rdlen)
    elif rrtype == 47:                                       # NSEC
        rdata = decode_nsec_rdata(pkt, offset, rdlen)
    elif rrtype in [48, 25, 60]:                             # [C]DNSKEY, KEY
        rdata = decode_dnskey_rdata(pkt, offset, rdlen)
    elif rrtype == 50:                                       # NSEC3
        rdata = decode_nsec3_rdata(pkt, offset, rdlen)
    elif rrtype == 51:                                       # NSEC3PARAM
        rdata = decode_nsec3param_rdata(pkt, offset, rdlen)
    elif rrtype in [52, 53]:                                 # TLSA, SMIMEA
        rdata = decode_tlsa_rdata(rdata)
    elif rrtype == 61:                                       # OPENPGPKEY
        rdata = decode_openpgpkey_rdata(rdata)
    elif rrtype in [64, 65]:                                 # SVCB, HTTPS
        rdata = RdataSVCB(pkt, offset, rdlen).__str__()
    elif rrtype == 257:                                      # CAA
        rdata = decode_caa_rdata(rdata)
    elif rrtype == 250:                                      # TSIG
        tsig_name = domainname
        tsig = options["tsig"]
        rdata = tsig.decode_tsig_rdata(pkt, offset, rdlen,
                                       tsig_name, orig_offset)
    else:                                                    # use RFC 3597
        rdata = generic_rdata_encoding(rdata, rdlen)
    offset += rdlen
    return (domainname, rrtype, rrclass, ttl, rdata, offset)


def decode_nsec_rr(pkt, offset):
    """ Decode an NSEC resource record; used by zonewalk() routine"""
    
    domainname, offset = name_from_wire_message(pkt, offset)
    rrtype, rrclass, ttl, rdlen = \
            struct.unpack("!HHIH", pkt[offset:offset+10])
    if rrtype != 47:
        raise ErrorMessage("encountered RR type %s, expecting NSEC" % rrtype)
    
    offset += 10
    rdata = pkt[offset:offset+rdlen]

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

