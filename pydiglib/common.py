
import os, sys, socket

PROGNAME       = os.path.basename(sys.argv[0])
PROGDESC       = "a DNS query tool written in Python"
VERSION        = "1.3.1"

PYVERSION      = sys.version_info.major
RESOLV_CONF    = "/etc/resolv.conf"    # where to find default server
DEFAULT_PORT   = 53
DEFAULT_PORT_TLS = 853
ITIMEOUT       = 0.5                   # initial timeout in seconds
RETRIES        = 3                     # how many times to try
TIMEOUT_MAX    = 10
BUFSIZE        = 65535                 # socket read/write buffer size
EDNS0_UDPSIZE  = 4096

size_query = 0
size_response = 0

class Stats:
    """Statistics counters"""
    compression_cnt = 0


USAGE_STRING = """\
{0} ({1}), version {2}

Usage: {0} [list of options] <qname> [<qtype>] [<qclass>]
       {0} @server +walk <zone>
Options:
        -h                        print program usage information
        @server                   server to query
        -pNN                      use port NN (default is port 53)
        -bIP                      use IP as source IP address
        +tcp                      send query via TCP
        +ignore                   ignore truncation (don't retry with TCP)
        +aaonly                   set authoritative answer bit
        +adflag                   set authenticated data bit
        +cdflag                   set checking disabled bit
        +norecurse                set rd bit to 0 (recursion not desired)
        +edns[=N]                 use EDNS with specified version (default 0)
        +ednsflags=N              set EDNS flags field to N
        +ednsopt=###[:value]      set generic EDNS option
        +bufsize=NN               use EDNS with specified UDP payload size
        +dnssec                   request DNSSEC RRs in response
        +hex                      print hexdump of rdata field
        +nsid                     send NSID (Name Server ID) option
        +expire                   send an EDNS Expire option
        +padding                  send an EDNS Padding option
        +cookie[=xxx]             send EDNS cookie option
        +subnet=addr              send EDNS client subnet option
        +chainquery[=name]        send EDNS chain query option
        +walk                     walk (enumerate) a DNSSEC secured zone
        +0x20                     randomize case of query name (bit 0x20 hack)
        -4                        perform queries using IPv4
        -6                        perform queries using IPv6
        -x                        reverse lookup of IPv4/v6 address in qname
        -d                        request additional debugging output
        -k/path/to/keyfile        use TSIG key in specified file
        -iNNN                     use specified message id
        -y<alg>:<name>:<key>      use specified TSIG alg, name, key
        +tls=auth|noauth          use TLS with|without authentication
        +tls_port=N               use N as the TLS port (default is 853)
        +tls_fallback             Fallback from TLS to TCP on TLS failure
        +tls_hostname=name        Check hostname in TLS server certificate
""".format(PROGNAME, PROGDESC, VERSION)


def dprint(input):
    if options["DEBUG"]:
        print(";; DEBUG: %s" % input)
    return


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
    """Print tracebacks for unexpected exceptions, not friendly errors."""
    if issubclass(exc_type, ErrorMessage):
        junk = sys.stderr.write("{}\n".format(exc_value))
    else:
        sys.__excepthook__(exc_type, exc_value, exc_traceback)


class Counter:
    """A simple counter class"""
    def __init__(self):
        self.max = None
        self.min = None
        self.count = 0
        self.total = 0
    def addvalue(self, val):
        if self.max == None:
            self.max = val
            self.min = val
        else:
            self.max = max(self.max, val)
            self.min = min(self.min, val)
        self.count += 1
        self.total += val
    def average(self):
        return (1.0 * self.total)/self.count


# Global dictionary of options: many options may be overridden or set in
# options.py: parse_args() by command line arguments.
options = dict(
    DEBUG=False,
    server=None,
    port=DEFAULT_PORT,
    srcip=None,
    use_tcp=False,
    ignore=False,
    aa=0,
    ad=0,
    cd=0,
    rd=1,
    use_edns=False,
    edns_version=0,
    edns_flags=0,
    ednsopt=[],
    bufsize=EDNS0_UDPSIZE,
    dnssec_ok=0,
    hexrdata=False,
    do_zonewalk=False,
    nsid=False,
    expire=False,
    padding=False,
    cookie=False,
    subnet=False,
    chainquery=False,
    do_0x20=False,
    ptr=False,
    af=socket.AF_UNSPEC,
    do_tsig=False,
    tsig_sigtime=None,
    unsigned_messages="",
    msgid=None,
    tls=False,
    tls_auth=False,
    tls_port=DEFAULT_PORT_TLS,
    tls_fallback=False,
    tls_hostname=None,
)
