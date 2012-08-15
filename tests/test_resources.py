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

    def test_dnskey(self):
        rdata = b'\x01\x01\x03\x08\x01\x03\xc3\xceWM\x98\xcb\xd9\x15~\rp\xd2t\xb8I\xca\x0e\x0e\xed\x9a\xff\xc5\xdc\xcc\x90GIi\x06e\\5\xcb\x08\xb3<M\x17\x1b\x01|\xa3V\xf4\x96\x02b\xaab\x93\xcd\xfa\xe8\xb1;U\xb2\x1c5\x1c\xdf\xa7h}8\xef\x07F_\x87\xf8M<\xcd\xab\x8a\xf2N\xde\xbda&\xbb\xfe\xa8w\xed\x9b\xa2\x08\x0f\xa2!\x1f\x18\xdc\xaf4\xf6\x92#\xb1N"\xba\x03\xb2|?\xb5\xa8\xcctW\xd5\x9e\xd2:#\xa2=c\xcd#\x04\x94\xc9c\x99\xef\xd5fq\rF.@\xba6V/\x1bq\xf0bl\xa7B\xfe\xa8\x17\x01\xaf\xfc\xa1\x0bK\x0e\xd9I\xda\xdbM\r\x07^\xf6[\xa8\xc5\x08\xec\x16\x8c\xb2I\xaf\x82mF\xee\x82\x99\xd5\x88\x85\xec\xefb\xa1S\\\xd3\xee\xc0I\xba\xa6d\xde\xd9\xf7\xc1\x06S\xf4!\xd8\xaf\xc1\x81G\xbc\x1e\xcd\x17U\xc7O*\xbbrbz\x10\x1d\xdd\xb2\x9c\xa3\xdc0\xc9S\x12(v\xffa\xc3\x1e4O\'f\xb2\xc0\x8aJ6{\xf8\xa0\xfa?'

        resource = DNSKEYResource.parse(rdata, 0 , len(rdata))
        self.assertEqual(bytes(resource), rdata)
