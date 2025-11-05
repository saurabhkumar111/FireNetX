# Threat Hunting — Practical Steps & Indicators
# Principle

Start with a hypothesis (e.g., "SSH brute force is happening") → collect data (PCAP, logs) → search for indicators → validate & document findings.

# Baselines

> Collect normal traffic baselines: typical ports, normal request rates, expected IPs and user-agents.

> Save ss -tuln, typical nmap output, normal apache2 access patterns.

# Indicators of compromise (IoCs) to search for

1. Repeated failed authentication followed by success.

2. Unusual outbound connections (rare ports, unknown IPs).

3. Data exfil patterns: large outbound transfers, DNS TXT queries carrying long base64 strings.

4. Scanning patterns: sequential port probes, many different URL paths returning 404.

# Commands & searches (quick)

SSH failed attempts (Ubuntu): 
```bash
grep "Failed password" /var/log/auth.log | tail -n 200
```

Recent successful logins: 

```bash
grep "Accepted" /var/log/auth.log | tail -n 200
```

Apache suspicious requests (many 404s): 

```bash
grep " 404 " /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -nr | head
```

Connections by remote IP from PCAP (tshark):
```bash
tshark -r firenetx_capture.pcap -T fields -e ip.src -e ip.dst -e frame.time_epoch | awk '{print $1" ->"$2" "$3}' | sort | uniq -c | sort -nr | head
```


## Correlation

> Match PCAP timestamps (UTC or local) with /var/log/* entries. Use tshark -r file.pcap -T fields -e frame.time_epoch to get epoch timestamps for matching.

Example correlation flow:

      1. Find a suspicious TCP connection in Wireshark and note frame.time_epoch and IPs/ports.

      2. Convert epoch to local time or search logs for the epoch range using awk/date.


## Investigation playbooks (mini)

a) SSH Brute-force:

    > Identify failed attempts in /var/log/auth.log.

    > Confirm in PCAP: multiple TCP SYNs to port 22 from the same source.

    > Check fail2ban status and banned IPs.

    > Block IP via ufw or update fail2ban jail configs.

b) Web reconnaissance / fuzzing:

    > Look for many 404s and repeated distinct URL paths.

    > In PCAP, inspect HTTP request payloads and User-Agent strings.

    > Identify source IPs and rate; throttle via firewall or mod_security.

## Documentation & evidence

Every finding should include: hypothesis, commands used, raw evidence (PCAP snippet or log excerpt), interpretation, and remediation suggestion.

Keep SHA256 sums of PCAPs and archives in **sha256sums.txt**.
