import sys
import argparse
import random
from struct import pack, unpack
import zokket

from dnstk.packet import Packet, Question
from dnstk.resources import Resource

class DNSClient(object):
    def __init__(self, args):
        resource = Resource.find(name=args.resource)
        if resource == Resource:
            print('Resource {} not supported.'.format(args.resource))
            sys.exit(0)
            return

        self.send(args.server, args.tcp, [Question(args.name,
            resource, args.cls)])

    def send(self, server, tcp=False, questions=[]):
        packet = Packet(int(random.random() * 1000), questions=questions)
        payload = bytes(packet)

        if tcp:
            sock = zokket.TCPSocket(self)
            sock.connect(server, 53)
            sock.read_until_length = 2
            sock.buffer_type = None
            self.payload = payload
        else:
            sock = zokket.UDPSocket(self)
            sock.bind()
            sock.send(server, 53, payload)

    def udp_socket_read_data(self, sock, host, port, data):
        self.parse_payload(data)
        sys.exit(0)

    def socket_did_connect(self, sock, host, port):
        sock.send(pack('>H', len(self.payload)))
        sock.send(self.payload)

    def socket_read_data(self, sock, data):
        if sock.read_until_length == 2:
            sock.read_until_length = unpack('>H', data)[0]
        else:
            self.parse_payload(data)
            sys.exit(0)

    def parse_payload(self, payload):
        try:
            packet = Packet.parse(payload)
        except:
            print('Unable to parse packet')
            return

        self.print_packet(packet)

    def print_packet(self, packet):
        print('Response code: {}'.format(packet.rcode))

        if packet.questions:
            print('Question section')

            for question in packet.questions:
                print(question)

            print()

        if packet.answers:
            print('Answer section')

            for answer in packet.answers:
                print(answer)

            print()

        if packet.authorities:
            print('Authoritive section')

            for authority in packet.authorities:
                print(authority)

            print()

        if packet.additional:
            print('Additional section')

            for additional in packet.additional:
                print(additional)

            print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--tcp', action='store_true')
    parser.add_argument('-r', '--resource', default='A')
    parser.add_argument('-c', '--cls', default='IN')
    parser.add_argument('-s', '--server', default='208.67.222.222')
    parser.add_argument('name')
    args = parser.parse_args()

    DNSClient(args)
    zokket.DefaultRunloop.run()

if __name__ == '__main__':
    main()

