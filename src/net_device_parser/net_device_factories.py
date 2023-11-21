"""Module with factories for NetDevice objects."""

from abc import ABC, abstractmethod

from .acl_parser import AccessListParser, CiscoIOSXEACLParser


class NetDeviceFactory(ABC):
    """Interface for net device factories.

    Contains all methods that a net device factory should expose.
    """
    @abstractmethod
    def get_acl_parser(self) -> AccessListParser:
        """Get a concrete ACL parser.

        Returns:
            A instance of a concrete ACL parser.
        """


class CiscoIOSXEFactory(NetDeviceFactory):
    """Net device factory for Cisco IOS XE devices."""

    def get_acl_parser(self) -> AccessListParser:
        return CiscoIOSXEACLParser()
