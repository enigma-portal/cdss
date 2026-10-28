"""Common HTTPS and destination checks for SIEM configuration and transport."""
import ipaddress
import socket
from urllib.parse import urlsplit


def parse_origin(value):
    parsed = urlsplit(value.strip())
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ('','/') or parsed.query or parsed.fragment
            or any(ord(char)<32 for char in value)):
        raise ValueError('Use an HTTPS URL without embedded credentials, path or query.')
    # Accessing port validates malformed and out-of-range explicit URL ports.
    parsed.port
    return parsed


def validate_destination(hostname, port):
    try:
        endpoints = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        addresses = {item[4][0] for item in endpoints}
    except socket.gaierror:
        raise ValueError('The SIEM hostname could not be resolved.') from None
    if not addresses:
        raise ValueError('The SIEM hostname could not be resolved.')
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise ValueError('Loopback, link-local, reserved and multicast SIEM destinations are blocked.')
    return endpoints


def validated_siem_endpoint(raw_url, raw_port, resolve=False):
    parsed = parse_origin(raw_url)
    try:
        port = int(raw_port)
    except (TypeError, ValueError):
        raise ValueError('Port must be a number between 1 and 65535.') from None
    if not 1 <= port <= 65535:
        raise ValueError('Port must be between 1 and 65535.')
    if parsed.port is not None and parsed.port != port:
        raise ValueError('The URL port and configured SIEM port must agree.')
    if resolve:
        validate_destination(parsed.hostname, port)
    host = '['+parsed.hostname+']' if ':' in parsed.hostname else parsed.hostname
    return 'https://'+host, port
