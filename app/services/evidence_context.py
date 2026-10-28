"""Comparison and presentation helpers; original evidence is never rewritten."""
import ipaddress
import re


def windows_path_equal(left, right):
    if not isinstance(left, str) or not isinstance(right, str) or not left or not right:
        return False

    def canonical(value):
        # Only rooted drive paths and explicit UNC paths have Windows semantics.
        if not (re.match(r'^[A-Za-z]:[\\/]', value) or value.startswith('\\\\')):
            return value
        value = value.replace('/', '\\')
        prefix = '\\\\' if value.startswith('\\\\') else ''
        return prefix + re.sub(r'\\+', lambda match: '\\', value[len(prefix):]).casefold()

    return canonical(left) == canonical(right)


def is_loopback(value):
    try:
        return ipaddress.ip_address(value).is_loopback
    except (ValueError, TypeError):
        return False


def network_label(value):
    return f'{value} (loopback/local-host)' if is_loopback(value) else value


def is_sysmon(fields):
    return (fields.get('provider_name') == 'Microsoft-Windows-Sysmon'
            and fields.get('channel') == 'Microsoft-Windows-Sysmon/Operational')
