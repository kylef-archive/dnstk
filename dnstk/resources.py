from struct import pack, unpack
import binascii
import socket

from dnstk.utils import parse_name, pack_name


class Resource(object):
    name = 'Unknown'
    value = None

    @classmethod
    def find(cls, name=None, value=None, use_none=False):
        if name and cls.name == name:
            return cls
        elif value and cls.value == value:
            return cls

        for subclass in cls.__subclasses__():
            c = subclass.find(name, value, True)
            if c:
                return c

        if use_none:
            return None

        return cls

    @classmethod
    def parse(cls, payload, offset, length):
        return cls(payload[offset:offset + length])

    def __init__(self, rdata=None):
        self.rdata = rdata

    def __bytes__(self):
        return self.rdata

    def __str__(self):
        return self.name


class AResource(Resource):
    name = 'A'
    value = 1

    @classmethod
    def parse(cls, payload, offset, length):
        if length != 4:
            return Resource.parse(payload, offset, length)

        ip = unpack('>BBBB', payload[offset:offset + length])
        return cls('.'.join([str(x) for x in ip]))

    def __init__(self, ip=None):
        self.ip = ip

    def __str__(self):
        return self.ip

    def __bytes__(self):
        return pack('>BBBB', *([int(x) for x in self.ip.split('.')]))


class NSResource(Resource):
    name = 'NS'
    value = 2

    @classmethod
    def parse(cls, payload, offset, length):
        ns = parse_name(payload, offset)[0]
        return cls(ns)

    def __init__(self, ns=''):
        self.ns = ns

    def __str__(self):
        return self.ns

    def __bytes__(self):
        return pack_name(self.ns)


class AAAAResource(AResource):
    name = 'AAAA'
    value = 28

    @classmethod
    def parse(cls, payload, offset, length):
        if length != 16:
            return Resource.parse(payload, offset, length)

        ip = socket.inet_ntop(socket.AF_INET6, payload[offset:length + offset])
        return cls(ip)

    def __bytes__(self):
        return socket.inet_pton(socket.AF_INET6, self.ip)

class CNAMEResource(Resource):
    name = 'CNAME'
    value = 5

    @classmethod
    def parse(cls, payload, offset, length):
        name = parse_name(payload, offset)[0]
        return cls(name)

    def __init__(self, name=None):
        self.cname = name

    def __str__(self):
        return self.cname

    def __bytes__(self):
        return pack_name(self.cname)


class SOAResource(Resource):
    name = 'SOA'
    value = 6

    @classmethod
    def parse(cls, payload, offset, length):
        mname, offset = parse_name(payload, offset)
        rname, offset = parse_name(payload, offset)

        serial = unpack('>I', payload[offset:offset + 4])[0]
        offset += 4

        refresh = unpack('>i', payload[offset:offset + 4])[0]
        offset += 4

        retry = unpack('>i', payload[offset:offset + 4])[0]
        offset += 4

        expire = unpack('>i', payload[offset:offset + 4])[0]
        offset += 4

        minimum = unpack('>i', payload[offset:offset + 4])[0]
        offset += 4

        return cls(mname, rname, serial, refresh, retry, expire, minimum)

    def __init__(self, mname='', rname='', serial=0, refresh=0, retry=0,
            expire=0, minimum=0):
        self.mname = mname
        self.rname = rname
        self.serial = serial
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.minimum = minimum

    def __bytes__(self):
        return (pack_name(self.mname) + pack_name(self.rname) +
                pack('>I', self.serial) +  pack('>i', self.refresh) +
                pack('>i', self.retry) + pack('>i', self.expire) +
                pack('>i', self.minimum))


class MXResource(Resource):
    name = 'MX'
    value = 15

    @classmethod
    def parse(cls, payload, offset, length):
        preference = unpack('>H', payload[offset:offset + 2])[0]
        offset += 2
        name = parse_name(payload, offset)[0]
        return cls(name, preference)

    def __init__(self, name=None, preference=0):
        self.mx = name
        self.preference = preference

    def __str__(self):
        return '{} {}'.format(self.preference, self.name)

    def __bytes__(self):
        return pack('>H', self.preference) + pack_name(self.mx)


class TXTResource(Resource):
    name = 'TXT'
    value = 16

    @classmethod
    def parse(cls, payload, offset, length):
        return cls(payload[offset:offset + length].decode())

    def __init__(self, data=None):
        self.data = data

    def __str__(self):
        return self.data

    def __bytes__(self):
        return self.data.encode()


class SSHFPResource(Resource):
    name = 'SSHFP'
    value = 44

    RSA = 1
    DSA = 2

    @classmethod
    def parse(cls, payload, offset, length):
        algorithm, fingerprint_type = unpack('>BB', payload[offset:offset+2])
        offset += 2
        fingerprint = binascii.hexlify(payload[offset:offset + length])
        return cls(fingerprint, algorithm, fingerprint_type)

    def __init__(self, fingerprint=None, algorithm=1, fingerprint_type=1):
        if isinstance(fingerprint, str):
            self.fingerprint = fingerprint.encode()
        else:
            self.fingerprint = fingerprint

        self.algorithm = algorithm
        self.fingerprint_type = fingerprint_type

    def __bytes__(self):
        return pack('>BB', self.algorithm, self.fingerprint_type) + \
                binascii.unhexlify(self.fingerprint)

class AXFRResource(Resource):
    name = 'AXFR'
    value = 252

