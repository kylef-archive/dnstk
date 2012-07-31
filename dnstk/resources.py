from struct import pack, unpack
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

    def __bytes__(self):
        return pack('>BBBB', *([int(x) for x in self.ip.split('.')]))


class CNAMEResource(Resource):
    name = 'CNAME'
    value = 5

    @classmethod
    def parse(cls, payload, offset, length):
        name = parse_name(payload, offset)[0]
        return cls(name)

    def __init__(self, name=None):
        self.cname = name

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

    def __bytes__(self):
        return pack('>H', self.preference) + pack_name(self.mx)

