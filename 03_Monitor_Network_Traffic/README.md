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

## Artifacts produced (recommended)

metadata.txt (tester, date_utc, kali_ip, ubuntu_ip, capture_iface, pcap_file)

firenetx_capture_<ts>.pcap

system_info.txt, ip_addr.txt, listening_ports_before.txt

ufw_status_before.txt, ssh_effective_config_before.txt

auth.log_initial, apache_access_initial.log, apache_error_initial.log

curl_http_response.txt, curl_https_response.txt, nmap_full_scan.txt

ssh_failed_attempts.log, web_fuzz_results.txt

tshark_http_summary.txt, auth_log_correlated.txt, apache_access_from_kali.txt

fail2ban_status.txt, fail2ban_details.txt

pcap_protocol_hierarchy.png, pcap_http_tx.png, pcap_tls_handshake.png

FireNetX_artifacts_YYYY-MM-DD.tar.gz

## File & naming conventions

Artifacts root: ~/FireNetX_artifacts

PCAP: firenetx_capture_YYYYMMDD_HHMMSS.pcap

Archive: FireNetX_artifacts_YYYY-MM-DD.tar.gz

Screenshots: pcap_protocol_hierarchy.png, pcap_http_tx.png, pcap_tls_handshake.png
