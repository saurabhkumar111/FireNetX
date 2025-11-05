# Common Network Traffic Types & What to Look For

## ARP

Purpose: L2 address resolution.

Look for: Excessive ARP requests (ARP storms), ARP spoofing (multiple MACs for same IP), unexpected gratuitous ARP.

## DHCP

Purpose: IP lease assignments.

Look for: Unexpected DHCP servers, repeated DHCPDISCOVER/OFFER loops.

## DNS

Purpose: Name resolution.

Look for: Large number of NXDOMAIN responses, requests to suspicious domains, data exfil over DNS (long encoded queries).

### HTTP / HTTPS

Purpose: Web traffic and APIs.

Look for: Strange user-agents, unusual POST payloads, abnormal URL patterns, high 404 rates (scanning), certificate anomalies for HTTPS.

## TLS/SSL

Purpose: Encrypted transport.

Look for: Weak ciphers, expired certificates, certificate mismatches, suspicious certificate chains.

## SSH

Purpose: Remote shell access.

Look for: Repeated failed auths (brute force), sudden successful logins from unusual IPs, new keys added to authorized_keys.

## ICMP

Purpose: Diagnostics and control.

Look for: High ICMP volume (scanning), ICMP tunneling, unreachable messages indicating routing issues.

## SMB / NetBIOS / Windows Protocols

Purpose: File sharing / domain operations.

Look for: Anonymous access attempts, unusual file access patterns, recon activity (SMB enumeration).

## NTP

Purpose: Time sync.

Look for: NTP amplification, unexpected NTP servers which may indicate misconfiguration.
