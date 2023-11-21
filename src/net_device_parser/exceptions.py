"""Exceptions for the package.

Contains all exceptions for the package.
"""


class NetDeviceParserException(Exception):
    """Base exception for all package exceptions."""


class IPAddressException(NetDeviceParserException):
    """Exception for IP addressess."""


class IPv4AddressException(IPAddressException):
    """Exception for IPv4 addressess."""


class AccessListParserException(NetDeviceParserException):
    """Base exception for Access List Parser exceptions."""


class ParserExceptionInvalidEntry(AccessListParserException):
    """Exception for invalid ACE line."""
