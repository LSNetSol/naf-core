"""Layer 1: collectors. Each parser turns raw protocol data into Python objects.

v0.2 status: parsers for BMP headers (RFC 7854), RTR IPv4 prefix PDUs (RFC 8210) and RFC 5424
syslog are implemented and tested. Live network sessions (gNMI subscribe, BMP/RTR TCP sessions,
IPFIX collection) are interfaces only and are planned for v0.5.
"""
