import unittest

from dnstk.resources import *

class ResourceTest(unittest.TestCase):
    def test_find(self):
        self.assertEqual(Resource.find('A'), AResource)
        self.assertEqual(Resource.find(), Resource)
        self.assertEqual(Resource.find(value=5), CNAMEResource)

    def test_a(self):
        rdata = b'\x7f\x00\x00\x01'
        ip = '127.0.0.1'

        self.assertEqual(AResource.parse(rdata, 0, 4).ip, ip)
        self.assertEqual(bytes(AResource(ip)), rdata)

    def test_cname(self):
        rdata = b'\x04test\x03com\x00'
        cname = 'test.com'

        self.assertEqual(CNAMEResource.parse(rdata, 0, len(rdata)).cname, cname)
        self.assertEqual(bytes(CNAMEResource(cname)), rdata)

    def test_mx(self):
        rdata = b'\x00\x01\x05ASPMX\x01L\nGOOGLEMAIL\x03COM\x00'
        mx = 'ASPMX.L.GOOGLEMAIL.COM'

        for resource in (MXResource.parse(rdata, 0, len(rdata)),
                MXResource(mx, 1)):
            self.assertEqual(resource.mx, mx)
            self.assertEqual(resource.preference, 1)
            self.assertEqual(bytes(resource), rdata)



