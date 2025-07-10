from asyncio import DatagramProtocol, Queue, get_running_loop
from typing import Any

from dnstk.packet import Packet


class UdpDnsProtocol(DatagramProtocol):
    def __init__(self):
        self.queue = Queue()

    # Delegate

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        self.queue.put_nowait((Packet.parse(data), addr))

    def error_received(self, exc: Exception) -> None:
        pass

    #

    async def read(self) -> tuple[Packet, tuple[str | Any, int]]:
        packet, addr = await self.queue.get()
        return (packet, addr)

    def send(self, packet: Packet, addr: Any = None) -> None:
        self.transport.sendto(bytes(packet), addr)


async def bind(host, port):
    _, protocol = await get_running_loop().create_datagram_endpoint(
        lambda: UdpDnsProtocol(), remote_addr=(host, port)
    )
    return protocol
