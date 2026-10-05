"""Static IANA special-address snapshot, not live routing or SSRF certification.

Both official registries last updated2025-10-09, fetched2026-10-05UTC.
IPv4: https://www.iana.org/assignments/iana-ipv4-special-registry/
IPv6: https://www.iana.org/assignments/iana-ipv6-special-registry/
Update: capture both complete CSVs, review every row/exception, regenerate and
rerun independent original/raw-table probes plus owned HTTP/TLS workflows.
No runtime network access or automatic refresh. Unknown/N/A/terminated rows
preserve stdlib fallback; True is not a guarantee of actual routability.
"""
from ipaddress import ip_network

# CSV SHA256 e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73
# CSV SHA256 775feea0621dec8735a44fbf30f762e721e8f0a1b3ab7eb341961a88cfce2139
REGISTRY_UPDATED = "2025-10-09"

_RULES = (
    ('0.0.0.0/32', False),
    ('192.0.0.8/32', False),
    ('192.0.0.9/32', True),
    ('192.0.0.10/32', True),
    ('192.0.0.170/32', False),
    ('192.0.0.171/32', False),
    ('192.88.99.2/32', False),
    ('255.255.255.255/32', False),
    ('192.0.0.0/29', False),
    ('192.0.0.0/24', False),
    ('192.0.2.0/24', False),
    ('192.31.196.0/24', True),
    ('192.52.193.0/24', True),
    ('192.88.99.0/24', None),
    ('192.175.48.0/24', True),
    ('198.51.100.0/24', False),
    ('203.0.113.0/24', False),
    ('169.254.0.0/16', False),
    ('192.168.0.0/16', False),
    ('198.18.0.0/15', False),
    ('172.16.0.0/12', False),
    ('100.64.0.0/10', False),
    ('0.0.0.0/8', False),
    ('10.0.0.0/8', False),
    ('127.0.0.0/8', False),
    ('240.0.0.0/4', False),
    ('::/128', False),
    ('::1/128', False),
    ('2001:1::1/128', True),
    ('2001:1::2/128', True),
    ('2001:1::3/128', True),
    ('::ffff:0.0.0.0/96', False),
    ('64:ff9b::/96', True),
    ('100::/64', False),
    ('100:0:0:1::/64', False),
    ('64:ff9b:1::/48', False),
    ('2001:2::/48', False),
    ('2001:4:112::/48', True),
    ('2620:4f:8000::/48', True),
    ('2001::/32', None),
    ('2001:3::/32', True),
    ('2001:db8::/32', False),
    ('2001:10::/28', None),
    ('2001:20::/28', True),
    ('2001:30::/28', True),
    ('2001::/23', False),
    ('3fff::/20', False),
    ('2002::/16', None),
    ('5f00::/16', False),
    ('fe80::/10', False),
    ('fc00::/7', False),
)
_NETWORKS = tuple((ip_network(prefix), value) for prefix,value in _RULES)

def reachable(value):
    """Most-specific known row; None means use existing non-registry fallback."""
    for network, reach in _NETWORKS:
        if value.version == network.version and value in network:
            return reach
    return None
