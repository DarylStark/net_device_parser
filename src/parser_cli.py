"""Access List parser for network devices."""

import logging

from rich.logging import RichHandler

from net_device_parser.models import (AccessListAction, AccessListEntry,
                                      AccessListProtocol, ACEIPv4Address,
                                      IPv4Address, IPv4Packet)

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[RichHandler()],
        format='%(message)s')

    ace = AccessListEntry(
        index_number=10,
        action=AccessListAction.PERMIT,
        protocol=AccessListProtocol.TCP,
        source_ipv4=ACEIPv4Address(
            address=IPv4Address('192.168.10.0'),
            wildcard_mask=IPv4Address('0.0.0.255')),
        destination_ipv4=ACEIPv4Address(
            address=IPv4Address('192.168.10.0'),
            wildcard_mask=IPv4Address('0.0.0.255')),
        destination_port=80)

    packet = IPv4Packet(
        protocol=AccessListProtocol.UDP,
        source_ipv4=IPv4Address('192.168.10.1'),
        source_port=5192,
        destination_ipv4=IPv4Address('8.8.8.8'),
        destination_port=53)

    print(ace.is_hit(packet))
