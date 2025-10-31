# 🛡️ Types of Network Threats

Network threats are malicious activities that target computer networks, systems, or data.  
Their goal is often to steal information, disrupt operations, or gain unauthorized access.  
Below are the most common types of network threats explained in simple terms.

---

## 1. **Viruses**
**What it is**  
A virus is a type of malicious program that attaches itself to legitimate files or applications. It requires some user action (opening a file, running a program) to execute and spread.

**How it works / spreads**  
Viruses are embedded in executable files, documents with macros, or installers. When the infected host program runs, the virus code executes and can modify other files or copy itself into other executables. It often spreads via email attachments, USB drives, or downloaded software.

**Impact / example**  
Viruses can corrupt or delete files, alter system behavior, slow performance, and provide a foothold for further attacks. *Example:* the ILOVEYOU virus (2000) spread via email attachments and caused widespread data loss and financial damage.

**Signs (indicators)**  
- Unexpected file changes or deletions.  
- Programs crash or behave oddly.  
- Sudden system slowdowns.  
- Antivirus alerts or quarantined files.

**Prevention & mitigation**  
- Keep operating systems and applications patched.  
- Use reputable antivirus/endpoint protection and update signatures frequently.  
- Disable or restrict macros in office documents.  
- Avoid opening unknown attachments or running software from untrusted sources.  
- Maintain regular backups and test restoration.
---

## 2. **Worms**
**What it is**  
A worm is self-contained malware that replicates and spreads across networks without requiring user action.

**How it works / spreads**  
Worms exploit vulnerabilities in network services, protocols, or devices. Once a worm infects a host, it scans the network for other vulnerable systems and copies itself to them. Some worms also carry payloads (e.g., installing backdoors or downloading additional malware).

**Impact / example**  
Worms can saturate network bandwidth, cause widespread outages, and deliver secondary payloads. *Example:* Conficker spread by exploiting Windows vulnerabilities and formed large botnets.

**Signs (indicators)**  
- Large amounts of unexpected network traffic.  
- Many identical outbound connections from one host.  
- Rapid appearance of the same malicious files across multiple machines.

**Prevention & mitigation**  
- Patch network-facing services promptly.  
- Restrict unnecessary services and ports.  
- Use network segmentation to limit lateral spread.  
- Deploy host-based and network-based intrusion detection systems.  
- Implement strong access controls and regular scanning for anomalies.

---

## 3. **Trojans (Trojan Horses)**
**What it is**  
A Trojan masquerades as legitimate software but contains a hidden malicious payload, such as a backdoor or credential stealer.

**How it works / spreads**  
Trojans rely on social engineering — tricking users into downloading or running them (e.g., pirated apps, fake installers, email attachments). After installation, a Trojan might open remote access for attackers, log keystrokes, or exfiltrate data.

**Impact / example**  
Trojans can give attackers persistent control, steal credentials, or be used to stage broader attacks. *Example:* Zeus infected machines to harvest online banking credentials.

**Signs (indicators)**  
- Unexpected new services or scheduled tasks.  
- Outbound connections to unknown servers, especially on nonstandard ports.  
- Sudden creation of user accounts or elevated privileges.

**Prevention & mitigation**  
- Only install software from trusted vendors and verify digital signatures.  
- Apply the principle of least privilege (avoid admin accounts for daily use).  
- Use up-to-date antivirus/EDR that detects suspicious behavior (not just signatures).  
- Monitor outbound traffic for connections to known command-and-control (C2) hosts.  
- Isolate and remediate infected hosts quickly; change credentials if compromise suspected.

---

## 4. **Phishing Attacks**
**What it is**  
Phishing uses deceptive messages (email, SMS, social media) or spoofed websites to trick users into revealing sensitive data or installing malware.

**How it works / spreads**  
Attackers craft convincing messages that create urgency or impersonate trusted entities. Victims click malicious links or provide credentials on cloned login pages. Spear-phishing targets specific individuals with tailored content.

**Impact / example**  
Phishing is a leading initial access vector — it can lead to credential theft, unauthorized access, financial fraud, or malware delivery. Common example: emails allegedly from a bank asking users to “verify” account details.

**Signs (indicators)**  
- Sender address that closely resembles a legitimate address but has small differences.  
- Links whose displayed text differs from the real URL (hover to reveal).  
- Generic greetings, urgent language, or unexpected attachments.  
- Requests for sensitive info via email.

**Prevention & mitigation**  
- Train users to recognize phishing (hover links, check senders, verify out-of-band).  
- Use email filtering, anti-phishing tools, and domain-based protections (DMARC, SPF, DKIM).  
- Enforce multi-factor authentication (MFA) to reduce damage from stolen credentials.  
- Simulate phishing exercises to improve awareness.

---

## 5. **Denial-of-Service (DoS) Attacks**
**What it is**  
A DoS attack aims to make services unavailable by overwhelming servers or network resources. A DDoS uses many distributed systems (often botnets) to amplify volume.

**How it works / spreads**  
Attackers send high volumes of traffic, exploit protocol weaknesses, or consume server resources (CPU/memory) with malformed requests. DDoS attacks often leverage compromised devices worldwide.

**Impact / example**  
Targets lose availability, causing business disruption and potential revenue loss. *Example:* Large DDoS campaigns can take down websites, APIs, or infrastructure (e.g., GitHub DDoS incidents).

**Signs (indicators)**  
- Sudden spike in inbound traffic.  
- Services become slow or unresponsive.  
- Anomalous traffic patterns from many IPs or repeated requests for a single resource.

**Prevention & mitigation**  
- Use DDoS protection services (CDNs, cloud scrubbing, rate-limiting).  
- Implement traffic filtering and anomaly detection.  
- Employ scalable infrastructure and redundancy.  
- Prepare an incident response plan and rate-limiting rules.  
- Monitor bandwidth and service metrics continuously.

---

## 6. **Man-in-the-Middle (MitM) Attacks**
**What it is**  
A MitM attack occurs when an attacker intercepts communication between two parties to eavesdrop, alter, or inject data.

**How it works / spreads**  
Common methods include ARP spoofing on local networks, DNS spoofing, or compromising routers. On unsecured Wi-Fi or networks lacking encryption, attackers can place themselves between users and services.

**Impact / example**  
Attackers can capture credentials, session tokens, or modify transactions (e.g., changing bank transfer details). MitM on public Wi-Fi is a frequent vector for credential theft.

**Signs (indicators)**  
- Unexpected certificate warnings in browsers.  
- User sessions dropping or being asked to re-authenticate often.  
- DNS responses that point to unusual IP addresses.  
- Presence of unfamiliar MAC addresses or gateways in ARP tables.

**Prevention & mitigation**  
- Use end-to-end encryption (HTTPS/TLS) for all sensitive communication.  
- Verify certificates and implement HSTS where possible.  
- Use VPNs on untrusted networks.  
- Harden network equipment (disable insecure management interfaces) and enable DNS security (DNSSEC) where supported.  
- Monitor ARP and DNS anomalies via IDS.
---

## 7. **Ransomware**
**What it is**  
Ransomware encrypts files and sometimes exfiltrates data, then demands payment to restore access or prevent disclosure.

**How it works / spreads**  
Ransomware can arrive via phishing attachments, exploited services, or compromised credentials. Some families also perform lateral movement across networks to encrypt many systems and targets backups.

**Impact / example**  
Organizations can lose critical data and suffer operational downtime; attackers may leak stolen data if ransom isn’t paid. *Example:* WannaCry exploited an SMB vulnerability and had global impact in 2017.

**Signs (indicators)**  
- Mass file renaming or sudden file read/write activity.  
- Documents become inaccessible and show unusual extensions.  
- Ransom notes appear on screens or in folders.  
- Backup failures or unexpected encryption of backups.

**Prevention & mitigation**  
- Maintain offline, versioned backups and test restores regularly.  
- Patch systems and close exposed services.  
- Employ endpoint protection and behavioral detection (block unusual encryption activity).  
- Use network segmentation to limit spread.  
- Enforce MFA and strong credential hygiene.  
- Have an incident response and communication plan ready.
---

## 8. **Insider Threats**
**What it is**  
Insider threats come from employees, contractors, or partners who misuse authorized access — intentionally or accidentally — causing harm.

**How it works / spreads**  
Insiders may exfiltrate data, leak credentials, or misconfigure systems. Accidents (e.g., mis-sent emails) can also expose data. Malicious insiders might be motivated by profit, grievance, or coercion.

**Impact / example**  
Insider actions can cause data breaches, intellectual property loss, regulatory fines, or reputational damage.

**Signs (indicators)**  
- Unusual access patterns: accessing data not needed for role, at odd hours, or large bulk downloads.  
- Attempts to bypass controls or disable logging.  
- Use of unauthorized external storage or email.  
- Sudden changes in user behavior or privilege escalation.

**Prevention & mitigation**  
- Apply the principle of least privilege and role-based access control (RBAC).  
- Use strong logging, monitoring, and user behavior analytics (UBA).  
- Implement data loss prevention (DLP) tools.  
- Conduct background checks and enforce separation of duties.  
- Provide regular security training and clear policies; investigate anomalies promptly.
---

## 9. **Zero-Day Exploits**
**What it is**  
A zero-day exploit targets a vulnerability unknown to the vendor and thus has no official patch available at the time of attack.

**How it works / spreads**  
Attackers discover or purchase zero-day vulnerabilities and create exploits to compromise systems before patches exist. Because defenders lack signatures or patches, detection and prevention are difficult.

**Impact / example**  
Zero-day attacks can lead to high-impact breaches, ransomware, or covert long-term access (APT). High-value targets and widely used software are attractive zero-day targets.

**Signs (indicators)**  
- Unexplained crashes or unusual behavior in software.  
- Indicators of compromise that don’t match known malware signatures.  
- Rapid, targeted attacks against specific software or systems.

**Prevention & mitigation**  
- Employ defense-in-depth: network segmentation, least privilege, strong monitoring, and application whitelisting.  
- Use behavior-based detection and anomaly detection (rather than relying solely on signatures).  
- Keep an emergency patching and response plan ready.  
- Subscribe to vendor advisories and threat intelligence feeds to react quickly when patches are released.  
- Employ virtual patching (WAF rules, IPS signatures) where possible until vendor fixes are available.

---

