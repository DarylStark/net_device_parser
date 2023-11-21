"""ACL parsers to parse access lists.

Contains a Interface that should be used for all parers.
"""


import logging
import re
from abc import ABC, abstractmethod

from .exceptions import ParserExceptionInvalidEntry
from .models import AccessListEntry, ACEIPv4Address, IPv4Address, AccessList


class AccessListParser(ABC):
    """Interface for Access List parsers."""

    @abstractmethod
    def parse_acl_config(self, acl: str) -> AccessList:
        """Parse a ACL from a plain text config.

        Interface method; should be overridden by specific parser.

        Args:
            acl: the config for the acl.
        """


class CiscoIOSXEACLParser(AccessListParser):
    """Access List parser for Cisco IOS XE configuration."""

    def __init__(self):
        """Set a ACL name and a empty ACE list."""
        self._logger = logging.getLogger('CiscoIOSXEACLParser')

    def parse_ace_config(self, ace_config: str) -> AccessListEntry:
        """Parse a specific ACE configline.

        Parses a Specific ACE config line and returns a AccessListEntry object.

        Args:
            ace_config: the configline for the ACE.

        Returns:
            A AccessListEntry object.

        Raises:
            ParserExceptionInvalidEntry: when the given line is not a valid ACE
                for a Cisco IOS XE device.
        """
        exploded_line = re.search(
            r'^\s+(?P<number>\d+)\s+(?P<action>permit|deny)\s+' +
            r'(?P<protocol>\S+)\s+(?P<line>.+)$',
            ace_config)
        if exploded_line:
            ace_entry = AccessListEntry(
                index_number=exploded_line.group('number'),
                action=exploded_line.group('action'),
                protocol=exploded_line.group('protocol')
            )

            # Change the words 'any' and 'host' to real numbers
            line = exploded_line.group('line')
            line = line.replace('any', '0.0.0.0 255.255.255.255')
            line = re.sub(r'host ([0-9.]+)', r'\1 0.0.0.0', line)

            # Get the sources and destinations
            ips = re.search(
                r'^(?P<source>(?P<src_ip>[0-9.]+)\s+' +
                r'(?P<src_wildcard>[0-9.]+)' +
                r'\s+(eq\s+(?P<src_port>[0-9]+)\s*)?)' +
                r'(?P<destination>(?P<dst_ip>[0-9.]+)\s+' +
                r'(?P<dst_wildcard>[0-9.]+)\s*(eq\s+(?P<dst_port>[0-9]+))?)$',
                line)

            if not ips:
                raise ParserExceptionInvalidEntry(
                    f'ACE not a valid Cisco IOS XE Entry: "{ace_config}"')

            ace_entry.source_ipv4 = ACEIPv4Address(
                address=IPv4Address(ips.group('src_ip')),
                wildcard_mask=IPv4Address(ips.group('src_wildcard'))
            )
            ace_entry.source_port = ips.group('src_port')

            ace_entry.destination_ipv4 = ACEIPv4Address(
                address=IPv4Address(ips.group('dst_ip')),
                wildcard_mask=IPv4Address(ips.group('dst_wildcard'))
            )
            ace_entry.destination_port = ips.group('dst_port')

            return ace_entry
        raise ParserExceptionInvalidEntry(
            f'ACE not a valid Cisco IOS XE Entry: "{ace_config}"')

    def parse_acl_config(self, acl: str) -> AccessList:
        """Parse a IOS XE ACL.

        Sets the specific ACEs in the ACL Parser.

        Args:
            acl: the config for the ACL.
        """
        # Find all entries
        aces: list[AccessListEntry] = []
        for ace_config in acl.split('\n'):
            try:
                aces.append(self.parse_ace_config(ace_config))
            except ParserExceptionInvalidEntry:
                self._logger.warning('Skipping invalid line "%s"', ace_config)
        return AccessList(aces=aces)
