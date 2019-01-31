import os, sys, socket, base64

from .common import *
from .util import *
from .tsig import Tsig, read_tsig_params


def set_tls_options(arg):
    """Set TLS options: authentication, fallback, hostname ..
       +tls={auth|noauth}
       +tls_port={N}
       +tls_fallback
       +tls_hostname={hostname}
    """
    if arg.startswith("+tls="):
        options["tls"] = True
        auth = arg[5:]
        if auth == "auth":
            options["tls_auth"] = True
        elif auth == "noauth":
            options["tls_auth"] = False
        else:
            raise ErrorMessage("Unsupported option: %s" % arg)
    elif arg.startswith("+tls_port="):
        options["tls_port"] = int(arg[10:])
    elif arg == "+tls_fallback":
        options["tls_fallback"] = True
    elif arg.startswith("+tls_hostname="):
        options["tls_hostname"] = arg[14:]
    else:
        raise ErrorMessage("Unsupported option: %s" % arg)

    return


def parse_args(arglist):
    """Parse command line arguments. Options must come first."""

    qtype = "A"
    qclass = "IN"
    
    i=0
    tsig = None
    
    for (i, arg) in enumerate(arglist):

        if arg.startswith('@'):
            options["server"] = arg[1:]

        elif arg == "-h":
            raise UsageError()

        elif arg.startswith("-p"):
            options["port"] = int(arg[2:])

        elif arg.startswith("-b"):
            options["srcip"] = arg[2:]

        elif arg == "+tcp":
            options["use_tcp"] = True

        elif arg == "+ignore":
            options["ignore"] = True

        elif arg.startswith("+tls"):
            set_tls_options(arg)

        elif arg == "+aaonly":
            options["aa"] = 1

        elif arg == "+adflag":
            options["ad"] = 1

        elif arg == "+cdflag":
            options["cd"] = 1

        elif arg == "+norecurse":
            options["rd"] = 0

        elif arg == "+edns":
            options["use_edns"] = True

        elif arg.startswith("+edns="):
            options["use_edns"] = True
            options["edns_version"] = int(arg[6:])

        elif arg.startswith("+ednsflags="):
            options["use_edns"] = True
            options["edns_flags"] = int(arg[11:])

        elif arg.startswith("+ednsopt="):
            options["use_edns"] = True
            parts = arg[9:].split(':', 1)
            code = int(parts[0])
            if len(parts) == 2:
                hexdata = parts[1]
            else:
                hexdata = ''
            options["ednsopt"].append((code, hexdata))

        elif arg.startswith("+bufsize="):
            options["use_edns"] = True
            options["bufsize"] = int(arg[9:])

        elif arg == "+dnssec":
            options["use_edns"] = True
            options["dnssec_ok"] = 1; 

        elif arg == "+hex":
            options["hexrdata"] = True

        elif arg == "+walk":
            options["do_zonewalk"] = True

        elif arg == "+nsid":
            options["use_edns"] = True
            options["nsid"] = True

        elif arg == "+expire":
            options["use_edns"] = True
            options["expire"] = True

        elif arg == "+cookie":
            options["use_edns"] = True
            options["cookie"] = True

        elif arg.startswith("+cookie="):
            options["use_edns"] = True
            options["cookie"] = arg[8:]
            
        elif arg.startswith("+subnet="):
            options["use_edns"] = True
            options["subnet"] = arg[8:]
            
        elif arg == "+chainquery":
            options["use_edns"] = True
            options["chainquery"] = True

        elif arg.startswith("+chainquery="):
            options["use_edns"] = True
            options["chainquery"] = arg[12:]

        elif arg == "+padding":
            options["use_edns"] = True
            options["padding"] = True

        elif arg.startswith("+padding="):
            options["use_edns"] = True
            options["padding"] = True
            options["padding_blocksize"] = int(arg[9:])

        elif arg == "+0x20":
            options["do_0x20"] = True

        elif arg == "+emptyquestion":
            options["emptyquestion"] = True

        elif arg == "-4":
            options["af"] = socket.AF_INET

        elif arg == "-6":
            options["af"] = socket.AF_INET6

        elif arg == "-x":
            options["ptr"] = True

        elif arg == "-d":
            options['DEBUG'] = True

        elif arg.startswith("-i"):
            options["msgid"] = int(arg[2:])

        elif arg.startswith("-k"):
            tsig = options["tsig"] = Tsig()
            tsig_file = arg[2:]
            name, key = read_tsig_params(tsig_file)
            tsig.setkey(name, key)
            options["do_tsig"] = True

        elif arg.startswith("-y"):
            if tsig:
                raise ErrorMessage("-y: attempt to re-specify TSIG parameters")
            tsig = options["tsig"] = Tsig()
            alg, name, key = arg[2:].split(":")
            key = base64.decodestring(key.encode())
            tsig.setkey(name, key, alg)
            options["do_tsig"] = True

        elif arg == "+https":
            options["https"] = True

        elif arg.startswith("+https="):
            options["https"] = True
            options["https_url"] = arg[7:]
            dprint("HTTPS URL set to: {}".format(options["https_url"]))

        else:
            break
    else:
        i += 1

    if not options["server"]:
        options["server"] = get_default_server()

    if options["emptyquestion"]:
        qname = None
    elif not arglist[i:]:
        qname = "."
        qtype = "NS"
    else:
        qname = arglist[i]

        if not options["do_zonewalk"]:
            if arglist[i+1:]:
                qtype = arglist[i+1].upper()
            if arglist[i+2:]:
                qclass = arglist[i+2].upper()

        if options["ptr"]:
            qname = ip2ptr(qname); qtype = "PTR"; qclass = "IN"
        elif qtype in ['OPENPGPKEY', 'SMIMEA'] and qname.find('@') != -1:
            qname = uid2ownername(qname, qtype)
        elif qtype.startswith("IXFR="):
            options["serial"] = int(qtype[5:])
            qtype = "IXFR"

        if not qname.endswith("."):
            qname += "."

    return (qname, qtype, qclass)

