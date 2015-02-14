"""
pydig is a library of routines used by the pydig - a python script
to perform a variety of DNS queries, loosely modelled on the BIND dig 
program. I wrote it mostly for fun, and to understand finer details of 
the DNS protocol.

Usage:

        pydig [list of options] <qname> [<qtype>] [<qclass>]
        pydig @server +walk <zone>

Options:

        -h                        print program usage information
        @server                   server to query
        -pNN                      use port NN
        -bIP                      use IP as source IP address
        +tcp                      send query via TCP
        +aaonly                   set authoritative answer bit
        +cdflag                   set checking disabled bit
        +norecurse                set rd bit to 0 (recursion not desired)
        +edns0                    use EDNS0 with 4096 octet UDP payload
        +dnssec                   request DNSSEC RRs in response
        +hex                      print hexdump of rdata field
        +walk                     walk (enumerate) a DNSSEC secured zone
        +0x20                     randomize case of query name (bit 0x20 hack)
        -4                        perform queries with IPv4
        -6                        perform queries with IPv6
        -d                        request additional debugging output
        -k/path/to/keyfile        use TSIG key in specified file
        -iNNN                     use specified message id
        -y<alg>:<name>:<key>      use specified TSIG alg, name, key

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

Limitations:

        Expects well formed (ie. correct) DNS responses. Otherwise
        it will likely generate an exception and terminate itself
        ungracefully.

        Certain combinations of options don't make any sense (eg.
        +tcp and +edns0). pydig doesn't bother to check that, and
        just ignores the nonsensical ones. Certain options also
        imply other options, eg. +walk and +dnssec imply +edns0.

        For TSIG (Transaction Signature) signed messages, the program
        supports HMAC-MD5/SHA1/SHA256/SHA384/SHA256. It doesn't yet
        support GSS-TSIG.

        It does not yet verify signatures in DNSSEC secured data.

        It does not perform iterative resolution (eg. dig's +trace).

Pre-requisites:

        Python 2.7 (or later) (Python 3.x not yet supported)

#
# Copyright (C) 2006 - 2015, Shumon Huque
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# pydig is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
# Author: Shumon Huque <shuque -@- gmail.com>
#
"""
