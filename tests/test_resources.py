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

    def test_aaaa(self):
        rdata = b"*\x02'p\x00\x00\x00\x00\x02\x1aJ\xff\xfe\xbf:\xcc"
        ip = '2a02:2770::21a:4aff:febf:3acc'

        self.assertEqual(AAAAResource.parse(rdata, 0, 16).ip, ip)
        self.assertEqual(bytes(AAAAResource(ip)), rdata)

    def test_cname(self):
        rdata = b'\x04test\x03com\x00'
        cname = 'test.com'

        self.assertEqual(CNAMEResource.parse(rdata, 0, len(rdata)).cname, cname)
        self.assertEqual(bytes(CNAMEResource(cname)), rdata)

    def test_soa(self):
        rdata = b'\x05apple\x03com\x00\x04root\x05apple\x03com\x00\x00' + \
            b'\x00\x00\x03\x00\x01Q\x80\x00\x00\x0e\x10\x00\t:\x80\x00\x00*0'
        mname = 'apple.com'
        rname = 'root.apple.com'

        for resource in (SOAResource.parse(rdata, 0, len(rdata)),
                SOAResource(mname, rname, 3, 86400, 3600, 604800, 10800)):
            self.assertEqual(resource.mname, mname)
            self.assertEqual(resource.rname, rname)
            self.assertEqual(resource.serial, 3)
            self.assertEqual(resource.refresh, 86400)
            self.assertEqual(resource.retry, 3600)
            self.assertEqual(resource.expire, 604800)
            self.assertEqual(resource.minimum, 10800)
            self.assertEqual(bytes(resource), rdata)

    def test_mx(self):
        rdata = b'\x00\x01\x05ASPMX\x01L\nGOOGLEMAIL\x03COM\x00'
        mx = 'ASPMX.L.GOOGLEMAIL.COM'

        for resource in (MXResource.parse(rdata, 0, len(rdata)),
                MXResource(mx, 1)):
            self.assertEqual(resource.mx, mx)
            self.assertEqual(resource.preference, 1)
            self.assertEqual(bytes(resource), rdata)

    def test_sshfp(self):
        rdata = b'\x01\x01\xdc\xaf+\xd0\xc3\xe9\x14PP\xfd\xed\xce\xd3(\x89\x9a\xacf\x19\xa3'
        fingerprint = b'dcaf2bd0c3e9145050fdedced328899aac6619a3'

        resource = SSHFPResource.parse(rdata, 0, len(rdata))
        self.assertEqual(fingerprint, resource.fingerprint)
        self.assertEqual(bytes(resource), rdata)


