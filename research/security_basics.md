# 🧱 Network Security Basics

This section covers essential security concepts like **firewalls**, **encryption**, and **secure network configurations** — the foundation of protecting any network from unauthorized access or data loss.

---

## 🔥 1. Firewalls

A **firewall** is a security device (hardware or software) that monitors and filters incoming and outgoing network traffic based on security rules.

### 🔹 Types of Firewalls
- **Packet-Filtering Firewall** – Checks packets individually based on IP, port, and protocol.  
- **Stateful Firewall** – Tracks active connections and allows traffic only if part of a valid session.  
- **Proxy Firewall** – Intermediary between users and the internet; inspects requests before forwarding.  
- **Next-Generation Firewall (NGFW)** – Adds features like application control, intrusion prevention, and deep packet inspection.

### 🔹 Example
**Windows:** Enable and configure *Windows Defender Firewall.*  
**Linux (UFW):**

sudo ufw enable
sudo ufw status
sudo ufw allow 22/tcp
sudo ufw deny 80/tcp


---

## 🔒 2. Encryption

**Encryption** is the process of converting readable data (plaintext) into an unreadable form (ciphertext) so that only authorized users can access it. It ensures **confidentiality**, **integrity**, and **authenticity** of information.

### 🔹 Types of Encryption
- **Symmetric Encryption** — Uses the same key for both encryption and decryption (e.g., AES, DES).  
- **Asymmetric Encryption** — Uses a public key to encrypt and a private key to decrypt (e.g., RSA, ECC).  
- **Hashing** — One-way encryption used for data integrity (e.g., SHA-256, MD5).  
- **Hybrid Encryption** — Combines symmetric and asymmetric methods for better performance and security.

### 🔹 Real-World Examples
- HTTPS websites use **TLS/SSL** to encrypt data between your browser and the server.  
- VPNs use encryption to secure all internet traffic through a virtual tunnel.  
- You can encrypt files on Linux using:

gpg -c filename.txt


---

## 3. Secure Network Configurations

Proper configuration of network devices ensures the network is not left open to attack.

### 🔹 Best Practices
- **Change default credentials** immediately after setup.  
- **Disable unused services and ports** to minimize the attack surface.  
- **Use strong Wi-Fi security standards** like WPA2 or WPA3.  
- **Keep firmware and OS updated** to patch vulnerabilities.  
- **Enable network segmentation** (e.g., separate guest network from internal).  
- **Implement logging and monitoring** to detect unusual traffic or failed logins.

### 🔹 Example (UFW on Linux)
Use these UFW commands to harden a Linux host quickly:

# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow essential services
sudo ufw allow 22/tcp         # SSH (change or restrict if not needed)
sudo ufw allow 80/tcp         # HTTP (only if hosting a web service)
sudo ufw allow 443/tcp        # HTTPS

# Deny a specific port
sudo ufw deny 23/tcp          # Telnet (example)

# Enable and check status
sudo ufw enable
sudo ufw status verbose

---

## 🧩 4. Monitoring Network Traffic (Using Wireshark)

Monitoring helps identify unusual or malicious activity in your network. **Wireshark** is a free and open-source packet analyzer used for this purpose.

### 🔹 Steps to Capture Traffic:
1. Open Wireshark and select the network interface (e.g., `eth0` or `wlan0`).
2. Start the capture by clicking the **blue shark fin** icon.
3. Visit some websites or generate traffic from other VMs.
4. Stop the capture after a few minutes and analyze the packets.

### 🔹 Common Protocols You’ll See:
- **HTTP / HTTPS** — Web traffic (port 80 / 443)  
- **DNS** — Domain name resolution (port 53)  
- **ICMP** — Ping or network testing packets  
- **TCP / UDP** — Core transport protocols  

### 🔹 Identifying Suspicious Traffic:
- Multiple failed connection attempts (possible scanning).  
- Unknown IPs sending repeated packets.  
- Data transfers using unusual ports (e.g., 1337, 6667).  
- High volume traffic from one source (possible DDoS).  

> 💡 **Tip:** Use Wireshark filters like `http`, `dns`, or `tcp.port == 22` to narrow down results.

---

## 📋 5. Documenting Your Findings

Documentation shows your understanding and helps others replicate your work.  

### 🔹 Include the following in your report:
- Summary of threats (from `threats.md`)  
- Security measures applied (firewall, encryption, configs)  
- Screenshots or `.pcap` files from Wireshark analysis  
- Explanation of how your measures reduced risk  

### 🔹 Example Folder Structure:

> 🧠 **Note:** Keep your captures and screenshots small to avoid repo bloat.

---

## 💭 6. Reflect on Security Best Practices

Think about how these measures scale to a larger environment.  

### 🔹 Reflection Points:
- How would you manage 50+ systems? → Use centralized firewall and patch management.  
- How would you detect insider threats? → Enable continuous monitoring and user behavior analytics.  
- How would you educate users? → Conduct awareness sessions on phishing, password safety, and data sharing.  

> "The best defense in cybersecurity is not just technology, but *informed users*."

---

## 🧠 7. Optional Enhancements (If You Want to Go Further)

If you want to make your project stand out:
- Install **Fail2Ban** on Ubuntu to auto-block failed SSH attempts.  
- Set up a **basic IDS** using `Snort` or `Suricata`.  
- Create a small **diagram** (using draw.io or Canva) showing your network topology.  
- Add a short **demo video** or animated GIF of Wireshark analysis in your GitHub repo.

---

## ✅ Final Outcome (Task 1 Complete)

By completing this task, you’ve:
- Understood common network threats and basic security concepts.  
- Configured a firewall (UFW).  
- Monitored real-time traffic using Wireshark.  
- Documented findings and reflections clearly.  


---
