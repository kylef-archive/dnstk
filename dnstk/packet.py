from struct import pack, unpack
from dnstk.resources import Resource
from dnstk.utils import parse_name, pack_name

DEFAULT_TTL = 518400

# Flags
DNS_CD = 0x0010 # checking disabled
DNS_AD = 0x0020 # authenticated data
DNS_Z =  0x0040 # unused
DNS_RA = 0x0080 # recursion available
DNS_RD = 0x0100 # recursion desired
DNS_TC = 0x0200 # truncated
DNS_AA = 0x0400 # authoritative answer

DNS_CLASS = {
    'IN': 1,
    'CS': 2,
    'CH': 3,
    'HS': 4,

# QUESTION_CLASS
    '*': 255,
}

def find_class(num):
    for cls in DNS_CLASS:
        if DNS_CLASS[cls] == num:
            return cls

    return 0

class Entry(object):
    @classmethod
    def parse(cls, payload, offset):
        name, offset = parse_name(payload, offset)
        resource = unpack('>H', payload[offset:offset + 2])[0]
        offset += 2
        c = unpack('>H', payload[offset:offset + 2])[0]
        offset += 2

        return cls(name, resource=Resource.find(value=resource), cls=find_class(c)), offset

    def __init__(self, name, resource=None, cls='IN'):
        self.name = name
        self.resource = resource or Resource
        self.cls = cls

    def __repr__(self):
        return '<{} ({} {} {})>'.format(self.__class__.__name__, self.name,
                self.resource, self.cls)

    def __bytes__(self):
        resource = self.resource or self.typ
        return (pack_name(self.name) + pack('>H', resource.value) +
            pack('>H', DNS_CLASS[self.cls]))


class Question(Entry): pass

class ResourceRecord(Entry):
    @classmethod
    def parse(cls, payload, offset):
        obj, offset = super(ResourceRecord, cls).parse(payload, offset)
        ttl = unpack('>I', payload[offset:offset + 4])[0]
        obj.ttl = ttl
        offset += 4
        rdata_length = unpack('>H', payload[offset:offset + 2])[0]
        offset += 2
        obj.resource = obj.resource.parse(payload, offset, rdata_length)
        offset += rdata_length

        return obj, offset

    def __init__(self, name='', ttl=DEFAULT_TTL, resource=None, cls='IN'):
        super(ResourceRecord, self).__init__(name, resource, cls)
        self.ttl = ttl

    def __repr__(self):
        return '<{} ({} {} {})>'.format(self.__class__.__name__, self.name,
                self.resource, self.cls)

    def __bytes__(self):
        rdata = bytes(self.resource)
        return (super(ResourceRecord, self).__bytes__() + pack('>I', self.ttl) +
                pack('>H', len(rdata)) + rdata)


class Packet(object):
    @classmethod
    def parse(cls, payload):
        offset = 12

        (txid, flags, questions, answers, authorities,
                additional) =  unpack('>HHHHHH', payload[:offset])

        sections = []
        for entries in ([Question] * questions, [ResourceRecord] * answers,
                [ResourceRecord] * authorities, [ResourceRecord] * additional):
            section = []
            for entry in entries:
                x, offset = entry.parse(payload, offset)
                section.append(x)
            sections.append(section)

        return cls(txid, flags, *sections)

    def __init__(self, txid=0, flags=DNS_RD, questions=None, answers=None,
            authorities=None, additional=None):
        self.txid = txid
        self.flags = flags
        self.questions = questions or []
        self.answers = answers or []
        self.authorities = authorities or []
        self.additional = additional or []

    def __repr__(self):
        return '<Packet ({}, {}, {}, {}, {})>'.format(self.txid,
                self.questions, self.answers, self.authorities,
                self.additional)

    def __bytes__(self):
        payload = pack('>HHHHHH',
            self.txid,
            self.flags,
            len(self.questions),
            len(self.answers),
            len(self.authorities),
            len(self.additional),
        )

        for entries in (self.questions, self.answers, self.authorities,
                self.additional):
            for entry in entries:
                payload += bytes(entry)

        return payload

    @property
    def is_response(self):
        return int((self.flags & 0x8000) == 0x8000)

    @is_response.setter
    def is_response(self, value):
        if value:
            self.flags |= 0x8000
        else:
            self.flags &= ~0x8000

    @property
    def rcode(self):
        return self.flags & 0xf

    @rcode.setter
    def rcode(self, value):
        self.flags = (self.flags & ~0xf) | (value & 0xf)

