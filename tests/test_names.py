import unittest
from struct import pack
from dnstk.utils import parse_name, pack_name

class NameTest(unittest.TestCase):
    def test_recursion(self):
        payload = b'\x05apple\x03com\x00\ndevelopers' + pack('>H', (0xc000 | 0))
        self.assertEqual(parse_name(payload, 11)[0], 'developers.apple.com')

    def test_infinite_recursion(self):
        payload = b'\x04loop' + pack('>H', (0xc000 | 0))
        self.assertRaises(RuntimeError, parse_name, payload, 0)

    def test_pack(self):
        self.assertEqual(pack_name('developers.apple.com'),
                b'\ndevelopers\x05apple\x03com\x00')

    def test_empty(self):
        self.assertEqual(pack_name(''), b'\x00')
        self.assertEqual(parse_name(b'\x00', 0)[0], '')
