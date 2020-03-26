import socket, struct, random, hashlib, binascii, string
from .common import *
from .util import *

class Name:

    """Class to represent domain names"""

    labels = None

    def __init__(self, labels, text=None):
        self.labels = labels
        if text:
            self.text = text

    def wire(self, canonical_form=False):
        """Return uncompressed wire format of domain name."""
        wire = b''
        for label in self.labels:
            if canonical_form:
                label = label.lower()
            wire += struct.pack('B', len(label)) + label
        return wire

    def text(self, escape=True):
        """Return textual representation of domain name."""
        result_list = []

        for label in self.labels:
            result = bytes2escapedstring(label,
                                         backslash_label, printables_label)
            result_list.append(result)

        if result_list == ['']:
            return "."
        else:
            return ".".join(result_list)

    def __repr__(self):
        return "<Name: {}>".format(self.text())


def name_from_text(input):
    """
    Return a Name() object corresponding to textual domain name.
    """
    labellist = []
    if input == ".":
        labellist = [b'']
    else:
        for label in input.split('.'):
            label = label.encode('ascii')
            labellist.append(label)
    return Name(labellist)


def name_from_wire_message(msg, offset):
    """
    Given wire format message, return a Name() object corresponding to the
    domain name at given offset in the message.
    """
    labels, offset = get_name_labels(msg, offset, [])
    return Name(labels), offset


def get_name_labels(msg, offset, c_offset_list):

    """
    Decode domain name at given packet offset. c_offset_list is a list 
    of compression offsets seen so far. Returns list of domain name labels.
    """

    labellist = []
    Done = False
    while not Done:
        llen, = struct.unpack('B', msg[offset:offset+1])
        if (llen >> 6) == 0x3:                 # compression pointer, sec 4.1.4
            Stats.compression_cnt += 1
            c_offset = struct.unpack('!H', msg[offset:offset+2])[0] & 0x3fff
            if c_offset in c_offset_list:
                raise ErrorMessage("Found compression pointer loop.")
            c_offset_list.append(c_offset)
            offset +=2
            rightmostlabels, _ = get_name_labels(msg, c_offset, c_offset_list)
            labellist += rightmostlabels
            Done = True
        else:
            offset += 1
            label = msg[offset:offset+llen]
            offset += llen
            labellist.append(label)
            if llen == 0:
                Done = True
    return (labellist, offset)


def name_match(n1, n2, case_sensitive=False):
    """Compare two Name objects"""
    if len(n1.labels) != len(n2.labels):
        return False
    for x, y in zip(n1.labels, n2.labels):
        if case_sensitive:
            if (x != y):
                return False
        else:
            if (x.lower() != y.lower()):
                return False
    else:
        return True


