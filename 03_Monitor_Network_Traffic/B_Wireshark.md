# Wireshark — Practical Notes for Task 3

## What to capture

 > Capture on the interface that sees traffic between Kali and Ubuntu (or host-only if applicable).

> Use -s0 (capture full packets) and avoid capture filters unless disk is a concern.

## Useful display filters (examples)

-> HTTP transactions: http

-> TLS handshakes: tls || ssl

-> SSH sessions: tcp.port == 22

->  queries/responses: dns

-> ARP: arp

-> ICMP: icmp

-> Conversations for an IP: ip.addr == 10.0.2.15

## Triage views to capture (take screenshots)

1. Protocol Hierarchy: Statistics → Protocol Hierarchy — saves protocol distribution.

2. HTTP transaction: filter http, locate a request & response pair, expand headers & body.

3. TLS handshake: filter tls and show ClientHello/ServerHello to inspect server certificate details.

---

## Saving evidence

When saving screenshots, include timestamp, display filter used, and the PCAP filename in the image filename.

Export the packet list (CSV) for events of interest: File → Export Packet Dissections → As CSV.
