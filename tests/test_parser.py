import unittest

from dnstk.packet import Packet

class ParserTest(unittest.TestCase):
    def test_packet(self):
        payload = b'l\x96\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04test\x03com\x00\x00\x01\x00\x01'
        packet = Packet.parse(payload)
        self.assertEqual(packet.__bytes__(), payload)

