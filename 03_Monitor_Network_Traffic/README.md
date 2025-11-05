# Task 3 — Network Traffic Monitoring (Summary) 

## Objective
Capture and analyze network traffic for the Ubuntu target, perform normal and controlled tests, collect logs and artifacts, correlate events between PCAP and system logs, and produce an evidence bundle for review.

## Quick one-line checklist

Choose capture host (Kali or Ubuntu).

Create artifacts folder: ~/FireNetX_artifacts (Ubuntu).

Save baseline: ss -tuln, sudo ufw status numbered, sudo sshd -T | grep -E 'passwordauthentication|pubkeyauthentication|permitrootlogin'.

Snapshot VM (pre-test).

Start packet capture (Kali): tcpdump -i <iface> -s0 -w firenetx_capture_<ts>.pcap.

Run normal tests (HTTP/HTTPS/DNS/SSH key login) and save outputs.

Run controlled tests (SSH failed attempts, limited web fuzzing) and save outputs.

Stop capture, copy PCAP into artifacts.

Open PCAP in Wireshark and take 3 screenshots.

Correlate PCAP timestamps with /var/log/auth.log and Apache logs; save grep results.

Save fail2ban status and ban lists.

Archive artifacts and snapshot VM (post-test).

## Tools Used
- Wireshark
- tcpdump
- tshark

## Labs
- Packet capture analysis
- Protocol dissection
- Traffic filtering
