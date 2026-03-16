"""IP classification helpers."""

from __future__ import annotations

from ipaddress import ip_address, ip_network

from fortipot.config import Settings
from fortipot.models import SourceClassification


def classify_ip(ip: str, settings: Settings) -> SourceClassification:
    """Classify an IP using allowlists and local CIDR rules."""

    candidate = ip_address(ip)
    if ip in settings.allowlists.ips:
        return SourceClassification.ALLOWLISTED
    if any(candidate in ip_network(cidr) for cidr in settings.allowlists.cidrs):
        return SourceClassification.ALLOWLISTED
    if any(candidate in ip_network(cidr) for cidr in settings.classification.local_cidrs):
        return SourceClassification.PRIVATE
    if settings.classification.treat_link_local_as_local and candidate.is_link_local:
        return SourceClassification.PRIVATE
    if candidate.is_private:
        return SourceClassification.PRIVATE
    if candidate.is_global:
        return SourceClassification.PUBLIC
    return SourceClassification.UNKNOWN
