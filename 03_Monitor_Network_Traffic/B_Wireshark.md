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

## Triage views to capture :

**1. Protocol Hierarchy: Statistics** → Protocol Hierarchy — saves protocol distribution.

<img width="857" height="898" alt="firenetx_screenshot_protocol_hierarchy" src="https://github.com/user-attachments/assets/8ff12763-d46c-44e1-a2cb-58b889e4f96e" />

**Observation:**
- Major traffic is under TCP.
- HTTP and TLS dominate, indicating normal web and encrypted sessions.

---

**2. HTTP transaction:** filter http, locate a request & response pair, expand headers & body.

<img width="848" height="796" alt="firenetx_screenshot_http_transaction" src="https://github.com/user-attachments/assets/8fb2aef6-3f95-416b-971a-55e3eedb65e4" />

**Observation:**
- The client requests a non-existent page (`/doesnotexist_22982.html`).
- The server returns a 302 redirect to HTTPS — showing Apache/2.4.52 on Ubuntu.

**3. TLS handshake:** filter tls and show ClientHello/ServerHello to inspect server certificate details.

<img width="857" height="833" alt="firenetx_screenshot_tls_handshake" src="https://github.com/user-attachments/assets/87352b78-ac8d-4302-afee-eb25dd897137" />


**Observation:**
- The connection starts with `Client Hello` and `Server Hello`.
- Secure encryption is established for subsequent HTTP traffic.



---

## Saving evidence

When saving screenshots, include timestamp, display filter used, and the PCAP filename in the image filename.

Export the packet list (CSV) for events of interest: File → Export Packet Dissections → As CSV.
