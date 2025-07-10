import argparse
import asyncio
import random
import sys
from struct import pack, unpack

from dnstk.packet import Packet, Question
from dnstk.resources import Resource
from dnstk.udp import bind


def print_packet(packet):
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


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--tcp', action='store_true')
    parser.add_argument('-r', '--resource', default='A')
    parser.add_argument('-c', '--cls', default='IN')
    parser.add_argument('-s', '--server', default='208.67.222.222')
    parser.add_argument('name')
    args = parser.parse_args()

    resource = Resource.find(name=args.resource)
    if resource == Resource:
        print('Resource {} not supported.'.format(args.resource), file=sys.stderr)
        sys.exit(1)

    packet = Packet(
        int(random.random() * 1000), questions=[Question(args.name, resource, args.cls)]
    )

    if args.tcp:
        (reader, writer) = await asyncio.open_connection(args.server, 53)
        writer.write(pack('>H', len(bytes(packet))))
        writer.write(bytes(packet))
        length = unpack('>H', await reader.read(2))[0]
        packet = Packet.parse(await reader.read(length))
    else:
        protocol = await bind(args.server, 53)
        protocol.send(packet)
        packet, _ = await protocol.read()

    print_packet(packet)


if __name__ == '__main__':
    asyncio.run(main())
