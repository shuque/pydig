import socket, struct, random, hashlib
from .common import *

class Struct:
    "Container class to emulate C struct or record."
    pass


def random_init():
    random.seed(os.urandom(64))
    return


def hexdump(input, separator=' '):
    """return a hexadecimal representation of the given string"""
    hexlist = ["%02x" % ord(x) for x in input]
    return separator.join(hexlist)


def h2bin(x):
    """turn hex dump string with optional whitespaces into binary string"""
    return x.replace(' ', '').replace('\n', '').decode('hex')


def packed2int(input):
    """convert arbitrary sized bigendian packed string into an integer"""
    sum = 0
    for (i, x) in enumerate(input[::-1]):
        sum += ord(x) * 2**(8*i)
    return sum


def randomize_case(input):
    """randomize case of input string; using the bit 0x20 hack to
    improve input entropy: see draft-vixie-dns-0x20-00"""
    outlist = []
    random.seed()
    for c in input:
        if c.isalpha():
            if random.choice([0,1]):
                outlist.append(chr((ord(c) ^ 0x20)))
                continue
        outlist.append(c)
    return "".join(outlist)


def domain_name_match(s1, s2, case_sensitive=False):
    if case_sensitive:
        return (s1 == s2)
    else:
        return (s1.lower() == s2.lower())
    

def ip2ptr(address):
    """return PTR owner name of an IPv4 or IPv6 address (for -x option)"""
    v4_suffix = '.in-addr.arpa.'
    v6_suffix = '.ip6.arpa.'
    error = False
    try:
        if address.find('.') != -1:                             # IPv4 address
            packed = socket.inet_pton(socket.AF_INET, address)
            octetlist = ["%d" % ord(x) for x in packed]
            ptrowner = "%s%s" % ('.'.join(octetlist[::-1]), v4_suffix)
        elif address.find(':') != -1:                           # IPv6 address
            packed = socket.inet_pton(socket.AF_INET6, address)
            hexstring = ''.join(["%02x" % ord(x) for x in packed])
            ptrowner = "%s%s" % \
                       ('.'.join([x for x in hexstring[::-1]]), v6_suffix)
        else:
            error = True
    except socket.error:
        error = True
    if error:
        raise ErrorMessage("%s isn't an IPv4 or IPv6 address" % address)
    
    return ptrowner


def get_socketparams(server, port, af, type):
    """Only the first set of parameters is used. Passing af=AF_UNSPEC prefers
    IPv6 if possible."""
    ai = socket.getaddrinfo(server, port, af, type)[0]
    family, socktype, proto, canonname, sockaddr = ai
    server_addr, port = sockaddr[0:2]
    return (server_addr, port, family, socktype)


def sendSocket(s, message):
    """Send message on a connected socket"""
    try:
        octetsSent = 0
        while (octetsSent < len(message)):
            sentn = s.send(message[octetsSent:])
            if sentn == 0:
                raise ValueError, "send() returned 0 bytes"
            octetsSent += sentn
    except Exception, diag:
        print("DEBUG: Exception: %s" % diag)
        return False
    else:
        return True


def recvSocket(s, numOctets):
    """Read and return numOctets of data from a connected socket"""
    response = ""
    octetsRead = 0
    while (octetsRead < numOctets):
        chunk = s.recv(numOctets-octetsRead)
        chunklen = len(chunk)
        if chunklen == 0:
            return ""
        octetsRead += chunklen
        response += chunk
    return response


def xor_string(a, b):
    """bitwise XOR bytes in a and b and return concatenated result"""
    result = ''
    for (x, y) in zip(a, b):
        result += chr(ord(x) ^ ord(y))
    return result


def hmac(key, data, func):
    """HMAC algorithm; see RFC 2104, 4635"""
    BLOCKSIZE = 64                             # 64 bytes = 512 bits
    ipad = '\x36' * BLOCKSIZE
    opad = '\x5c' * BLOCKSIZE

    key = "%s%s" % (key, '\x00' * (BLOCKSIZE - len(key)))  # pad to blocksize

    m = func()
    m.update("%s%s" % (xor_string(key, ipad), data))
    r1 = m.digest()

    m = func()
    m.update("%s%s" % (xor_string(key, opad), r1))

    return m.digest()

                                
def txt2domainname(input, canonical_form=False):
    """turn textual representation of a domain name into its wire format"""
    if input == ".":
        d = '\x00'
    else:
        d = ""
        for label in input.split('.'):
            if canonical_form:
                label = label.lower()
            length = len(label)
            d += struct.pack('B', length) + label
    return d


def get_domainname(pkt, offset):
    """decode a domainname at the given packet offset; see RFC 1035"""
    global count_compression
    labellist = []               # a domainname is a sequence of labels
    Done = False
    while not Done:
        llen, = struct.unpack('B', pkt[offset])
        if (llen >> 6) == 0x3:                 # compression pointer, sec 4.1.4
            count_compression += 1
            c_offset, = struct.unpack('!H', pkt[offset:offset+2])
            c_offset = c_offset & 0x3fff       # last 14 bits
            offset +=2
            rightmostlabels, junk = get_domainname(pkt, c_offset)
            labellist += rightmostlabels
            Done = True
        else:
            offset += 1
            label = pkt[offset:offset+llen]
            offset += llen
            labellist.append(label)
            if llen == 0:
                Done = True
    return (labellist, offset)


def pdomainname(labels):
    """given a sequence of domainname labels, return a printable string"""
    if len(labels) == 1:          # list with 1 empty label is the root
        return "."
    else:
        return ".".join(labels)


def uid2ownername(uid, qtype):
    """Return OPENPGPKEY/SMIMEA ownername for given uid/email address"""
    if qtype == 'OPENPGPKEY':
        applabel = '_openpgpkey'
    elif qtype == 'SMIMEA':
        applabel = '_smimecert'
    else:
        raise ValueError('Invalid qtype for uid2owner')
    localpart, rhs = uid.split('@')
    h = hashlib.sha256()
    h.update(localpart)
    owner = "%s.%s.%s" % (h.hexdigest()[0:56], applabel, rhs)
    if not owner.endswith('.'):
        owner = owner + '.'
    return owner
