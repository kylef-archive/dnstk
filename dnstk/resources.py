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

