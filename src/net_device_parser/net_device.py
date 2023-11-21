"""Module with the NetDevice class."""

from .net_device_factories import NetDeviceFactory
from .acl_parser import AccessListParser


class NetDevice:
    """Class to initiate Net Devices.

    A Net Device is a networking device. By using a factory, the user can
    specify how this device behaves.
    """

    def __init__(self, net_device_factory: NetDeviceFactory):
        """Set the factory object.

        Args:
            net_device_factory: a instance of a NetDeviceFactory instance that
                will be used to define objects within the object.
        """
        self.net_device_factory = net_device_factory

    def get_acl_parser(self) -> AccessListParser:
        """Get a ACL parser.

        Returns a ACL Parser that is relevant for this specific net device.

        Returns:
            AccessListParser: a ACL parser that is relevant for this specific
                net device. For Cisco devices, this will be different then for
                FortiGate devices.
        """
        return self.net_device_factory.get_acl_parser()
