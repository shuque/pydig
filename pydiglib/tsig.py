import hashlib, time, base64
from .common import *
from .util import *
from .dnsparam import *
from .name import *


# TSIG algorithms: see RFC 2845 (hmac-md5), 3645 (gss-tsig), 4635 (hmac-sha*)
# GSS-TSIG is not yet implemented.
dns_tsig_alg = {
    "hmac-md5"    : ("hmac-md5.sig-alg.reg.int.", hashlib.md5),
    "gss-tsig"    : ("gss-tsig.", None),
    "hmac-sha1"   : ("hmac-sha1.", hashlib.sha1),
    "hmac-sha224" : ("hmac-sha224.", hashlib.sha224),
    "hmac-sha256" : ("hmac-sha256.", hashlib.sha256),
    "hmac-sha384" : ("hmac-sha384.", hashlib.sha384),
    "hmac-sha512" : ("hmac-sha512.", hashlib.sha512),
    }
dns_tsig_alg_len = {
    "hmac-md5"    : 16,
    "gss-tsig"    : None,
    "hmac-sha1"   : 20,
    "hmac-sha224" : 28,
    "hmac-sha256" : 32,
    "hmac-sha384" : 48,
    "hmac-sha512" : 64,
    }


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
    return b'\x00\x00' + struct.pack('!I', sigtime)  # 48-bits


class Tsig:
    """TSIG Object Class: encapsulates TSIG related methods and data"""
    def __init__(self):
        self.keyname = None
        self.key = None
        self.algorithm = None
        self.algorithm_len = None
        self.function = None
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
        self.keyname = name_from_text(name)
        self.key = key
        if algorithm == None:
            raise ErrorMessage("unsupported TSIG algorithm %s" % algorithm)
        self.algorithm, self.function = dns_tsig_alg.get(algorithm)
        self.algorithm_len = dns_tsig_alg_len.get(algorithm)
        self.algorithm = name_from_text(self.algorithm)

    def get_rr_length(self):
        """
        Pre-calculate TSIG RR's length even before the TSIG RR contents are
        computed. This is needed to figure out the amount of EDNS padding,
        since the padding option in the OPT RR precedes the TSIG RR.
        """
        return len(self.keyname.wire()) + 10 + \
            len(self.algorithm.wire()) + 16 + \
            self.algorithm_len

    def mk_request_tsig(self, msgid, msg):
        """Create TSIG (Transaction Signature) RR; see RFC 2845; currently"""

        # strictly speaking, we only need tsig name/alg in canonical form
        # for the MAC computation, but we'll use them in the RR also ..
        tsig_name = self.keyname.wire(canonical_form=True)
        tsig_type = struct.pack('!H', qt.get_val("TSIG"))
        tsig_class = struct.pack('!H', qc.get_val("ANY"))
        tsig_ttl = struct.pack('!I', 0)
        tsig_alg = self.algorithm.wire(canonical_form=True)
        now = int(time.time())
        tsig_sigtime = mk_tsig_sigtime(now)
        tsig_fudge = struct.pack('!H', self.request.fudge)
        tsig_error = struct.pack('!H', 0)                     # NOERROR
        tsig_otherlen = struct.pack('!H', 0)
        data = (msg + tsig_name + tsig_class + tsig_ttl + tsig_alg +
                tsig_sigtime + tsig_fudge + tsig_error + tsig_otherlen)
        mac = hmac(self.key, data, self.function)
        mac_size = struct.pack('!H', len(mac))
        self.request.mac = mac
        self.origid = struct.pack('!H', msgid)
        rdata = (tsig_alg + tsig_sigtime + tsig_fudge +
                 mac_size + mac + self.origid + tsig_error + tsig_otherlen)
        rdlen = struct.pack('!H', len(rdata))
        self.request.tsig = (tsig_name + tsig_type + tsig_class + tsig_ttl +
                             rdlen + rdata)
        return self.request.tsig
    
    def decode_tsig_rdata(self, pkt, offset, rdlen, tsig_name, tsig_offset):
        """decode TSIG rdata: alg, sigtime, fudge, mac_size, mac, origid,
        error, otherlen; see RFC 2845"""

        self.tsig_total += 1
        self.response.msg = pkt
        self.response.tsig_offset = tsig_offset
        self.response.tsig_name = tsig_name
        d, offset = name_from_wire_message(pkt, offset)
        self.response.alg = d
        if not name_match(self.response.alg, self.algorithm):
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
                 (self.response.alg.text(),
                  self.response.sigtime,
                  self.response.fudge,
                  self.response.mac_size,
                  mac_base64,
                  self.response.origid,
                  rc.get_name(self.response.error),
                  self.response.otherlen)
        if self.response.otherlen != 0:          # only for BADTIME ercode
            self.response.otherdata = pkt[offset:offset+otherlen]
            result += str(self.response.otherdata)
        else:
            self.response.otherdata = b""
        self.verify_tsig()
        return result

    def verify_tsig(self):
        """Verify TSIG record if possible; see RFC 2845, Section 3.4 & 4
        Reconstruct packet before TSIG record was added, and with origid;
        add TSIG variables, and request MAC; compute digest and compare it
        with received digest."""
    
        if not name_match(self.response.tsig_name, self.keyname):
            raise ErrorMessage("encountered unknown TSIG key name: %s" %
                               self.response.tsig_name)

        request_mac = (struct.pack('!H', len(self.request.mac)) +
                       self.request.mac)

        data = self.response.msg[:self.response.tsig_offset]
        arcount, = struct.unpack('!H', data[10:12])
        dns_message = (struct.pack('!H', self.response.origid) + data[2:10] +
                       struct.pack('!H', arcount-1) + data[12:])

        tsig_name = self.response.tsig_name.wire(canonical_form=True)
        tsig_class = struct.pack('!H', qc.get_val("ANY"))
        tsig_ttl = struct.pack('!I', 0)
        tsig_alg = self.algorithm.wire(canonical_form=True)
        tsig_sigtime = mk_tsig_sigtime(self.response.sigtime)
        tsig_fudge = struct.pack('!H', self.response.fudge)
        tsig_error = struct.pack('!H', self.response.error)
        tsig_otherlen = struct.pack('!H', self.response.otherlen)
        tsig_otherdata = self.response.otherdata
        tsig_vars = (tsig_name + tsig_class + tsig_ttl + tsig_alg + 
                     tsig_sigtime + tsig_fudge + tsig_error +
                     tsig_otherlen + tsig_otherdata)

        if self.prior_digest:
            input_data = (struct.pack('!H', len(self.prior_digest)) +
                          self.prior_digest + 
                          dns_message + tsig_sigtime + tsig_fudge)
        else:
            input_data = (request_mac + dns_message + tsig_vars)
        computed_mac = hmac(self.key, input_data, self.function)
        # Support Truncation: compare only first self.response.mac_size bits
        if computed_mac[0:self.response.mac_size] != self.response.mac[0:self.response.mac_size]:
            print("WARNING: TSIG record verification failed.")
            self.verify_failure += 1
        else:
            self.verify_success += 1
        if abs(self.response.sigtime - int(time.time())) > self.request.fudge:
            print("WARNING: TSIG signature time exceeds clock skew.")

        self.prior_digest = self.response.mac          # for AXFR
        return


