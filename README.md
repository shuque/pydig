# pydig

Program:	pydig (a DNS query tool written in Python)  
Written by:	Shumon Huque <shuque@gmail.com>  

## Description

pydig is a program to perform DNS queries and exercise various existing
and emerging features of the DNS protocol. It is roughly modelled after the
dig program that comes with ISC BIND. I wrote it mostly for fun, and to
help me learn learn some of the more esoteric features of the DNS. Occasionally
I use it to quickly prototype new and proposed enhancements to the DNS. Some of
the more recent such features include EDNS client subnet, chain query, cookies,
DNS over TLS, EDNS padding, DNS over HTTPS, and more.

RR type and class codes (qtype and qclass) unknown to this program can be
specified with the TYPE123 and CLASS123 syntax.

## Usage

```
$ pydig -h
pydig (a DNS query tool written in Python), version 1.6.1

Usage: pydig [list of options] <qname> [<qtype>] [<qclass>]
       pydig @server +walk <zone>
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
        +cookie[=xxx]             send EDNS cookie option
        +subnet=addr              send EDNS client subnet option
        +chainquery[=name]        send EDNS chain query option
        +padding[=N]              send EDNS padding option (defblocksize 128)
        +walk                     walk (enumerate) a DNSSEC secured zone
        +0x20                     randomize case of query name (bit 0x20 hack)
        +emptyquestion            send an empty question section
        +generic                  use RFC3597 generic type/class/rdata format
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
        +https[=url]              use HTTPS transport with optional URL
``

IXFR (Incremental Zone Transfer) queries are supported with the syntax
of "IXFR=NNNN" for the <qtype>, where NNNN is the zone serial number.

```
Example usage:

       pydig www.example.com
       pydig www.example.com A
       pydig www.example.com A IN
       pydig @10.0.1.2 example.com MX
       pydig @dns1.example.com _blah._tcp.foo.example.com SRV
       pydig @192.168.42.6 +dnssec +norecurse blah.example.com NAPTR
       pydig @dns2.example.com -6 +hex www.example.com
       pydig @192.168.72.3 +walk secure.example.com
       pydig @192.168.14.7 -yhmac-md5:my.secret.key.:YWxidXMgZHVtYmxlZG9yZSByaWNoYXJkIGRhd2tpbnM= example.com axfr
       pydig @192.168.14.7 -yhmac-sha256:my.secret.key.:NBGFWFr+rR/uu14B94Ab1+u81M2DTqB65gOv16nG8Xw= example.com axfr
       pydig @185.49.141.38 +tls=auth +tls_hostname=getdnsapi.net www.ietf.org AAAA
       pydig +padding=256 blah.example.com AAAA
       pydig +https www.ietf.org A
```

# Additional Notes

For TSIG (Transaction Signature) signed messages, the program supports
HMAC-MD5/SHA1/SHA256/SHA384/SHA256. It doesn't yet support GSS-TSIG.

It decodes but does not yet verify signatures in DNSSEC secured data.

It does not perform iterative resolution (eg. dig's +trace).

Specific features of TLS depend on the version of Python in use. TLS server
certificate verification and hostname verification require quite recent
versions of Python.

HTTPS support requires the "requests" module. If no URL is specified via
the +https option, then by default Cloudflare's DNS over HTTPS server is
queried (https://cloudflare-dns.com/dns-query).


# Pre-requisites:

* Python 3


# Installation:

1. (as root) python3 setup.py install

# License

Shumon Huque
E-mail: shuque -at- gmail.com
Web: https://www.huque.com/

Copyright (c) 2006 - 2017, Shumon Huque. 
All rights reserved. This program is free software; you can redistribute 
it and/or modify it under the same terms of the GNU General Public License.
