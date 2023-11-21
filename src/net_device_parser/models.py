"""Models for the package.

This module contains all models that are used throughout the package.
"""

import math
import re
from enum import Enum

from pydantic import BaseModel

from .exceptions import IPv4AddressException


class AccessListAction(Enum):
    """Enum with possible ACE actions.

    Contains all possible actions for a Access List Entry.
    """
    DENY = 'deny'
    PERMIT = 'permit'


class AccessListProtocol(Enum):
    """Protocols that are possible in a ACE.

    Contains all protocols that are possible to set in a Access List Entry.
    """
    IP = 'ip'
    UDP = 'udp'
    TCP = 'tcp'
    ICMP = 'icmp'


class IPv4Address(BaseModel):
    """Dataclass for IPv4 addresses."""
    ip: int = 0

    def _from_string(self, ip: str) -> int:
        """Convert a dotted-quad format to a integer.

        Args:
            ip: the IPv4 address in dotted-quad format (x.x.x.x)

        Returns:
            The IPv4 address as integer.

        Raises:
            IPv4AddressException: when the given IPv4 address is not a valid
                IPv4 address.
        """
        octets = re.search(r'^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$', ip)
        if octets:
            final_number = 0
            for index, octet in enumerate(range(1, 5)):
                octet_numeric = int(octets[octet])
                final_number += octet_numeric << ((3 - index) * 8)
            return final_number
        raise IPv4AddressException(f'IPv4 address "{ip}" is invalid')

    def __str__(self) -> str:
        """String representation of the IPv4 address.

        Returns:
            The dotted-quad format of the IPv4 address.
        """
        octets: list[int] = []
        for octet in range(0, 4):
            bitshift = (3 - octet) * 8
            number = (self.ip & (255 << bitshift)) >> bitshift
            octets.append(str(number))
        return '.'.join(octets)

    def __init__(self, ip: int | str | None, *args, **kwargs) -> None:
        """Set the fields.

        Aargs:
            ip: the IPv4 address. Can be either a integer or a string.
        """
        if isinstance(ip, str):
            ip = self._from_string(ip)

        if ip < 0 or ip >= math.pow(2, 32):
            raise IPv4AddressException(f'IPv4 address "{ip}" is invalid')

        super().__init__(ip=ip, *args, **kwargs)


class ACEIPv4Address(BaseModel):
    """Dataclass for IPv4 entries in a ACE.

    Contain a address to specify the addresses in the ACE and a wildcard mask
    to specify what addresses match.
    """
    address: IPv4Address
    wildcard_mask: IPv4Address


class AccessList(BaseModel):
    """Dataclass for Access Lists.

    Contains all information about a access list.
    """
    aces: list['AccessListEntry'] = []


class IPv4Packet(BaseModel):
    """Dataclass for a IP packet.

    Can be used to check if a Access List is hit.
    """
    protocol: AccessListProtocol
    source_ipv4: IPv4Address
    source_port: int | None = None
    destination_ipv4: IPv4Address
    destination_port: int | None = None


class AccessListEntry(BaseModel):
    """Dataclass for a Access List Entry.

    Contains all information for a access list entry and a method to specify if
    a specific packet is allowed through.

    If any of the fields:

        source_ipv4, source_port, destination_ipv4 and destination_port

    is set to None, it indicates a ANY.
    """
    index_number: int
    action: AccessListAction
    protocol: AccessListProtocol
    source_ipv4: ACEIPv4Address = None
    source_port: int | None = None
    destination_ipv4: ACEIPv4Address = None
    destination_port: int | None = None

    def is_hit(self, packet: IPv4Packet) -> bool:
        """Check if this ACE is hit by a specific IP packet.

        Args:
            packet: the packet to compare to this ACE.

        Returns:
            bool: True if this ACE is hit by this packet, False if it isn't hit
                by this packet.
        """
        raise NotImplemented
