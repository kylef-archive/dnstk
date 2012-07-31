import unittest

from dnstk.resources import *

class ResourceTest(unittest.TestCase):
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



