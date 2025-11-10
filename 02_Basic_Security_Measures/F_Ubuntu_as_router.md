# FireNetX — Ubuntu Router Verification (IPv4-Only Routing)

This document explains how Kali Linux routes **all IPv4 traffic** through an Ubuntu VM acting as a router.  
This setup uses **Host-Only** + **Bridged** adapters in VirtualBox and simulates a real network perimeter.

✅ IPv4 is routed via Ubuntu  
✅ Ubuntu performs NAT (MASQUERADE)  
✅ Kali sees the internet through the router  
✅ IPv6 bypasses Ubuntu (by design for this project)

---

# 🖥️ Network Architecture

```
                   +-----------------------+
                   |     Home Router       |
                   |   192.168.31.1/24     |
                   +-----------+-----------+
                               |
                           (Bridged)
                               |
                    +----------▼-----------+
                    |     Ubuntu Router    |
                    |  enp0s3 (WAN):       |
                    |   192.168.31.23      |
                    |                      |
                    |  enp0s8 (LAN):       |
                    |   192.168.56.102     |
                    +----------+-----------+
                               |
                         (Host-Only)
                               |
                    +----------▼-----------+
                    |        Kali          |
                    | 192.168.56.101/24    |
                    +-----------------------+
```

---

# ✅ Ubuntu Router Configuration

## 1. Enable IPv4 forwarding
```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-ipv4.conf
sudo sysctl --system
```

## 2. Clean iptables safely (without breaking SSH)
```bash
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

sudo iptables -F
sudo iptables -t nat -F
```

## 3. NAT for IPv4 (LAN → WAN)
```bash
sudo iptables -t nat -A POSTROUTING -s 192.168.56.0/24 -o enp0s3 -j MASQUERADE
```

## 4. Forward LAN <→ WAN traffic
```bash
sudo iptables -A FORWARD -i enp0s8 -o enp0s3 -j ACCEPT
sudo iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

## 5. Keep SSH accessible
```bash
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
```

## 6. Save rules
```bash
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

---

# ✅ Kali Configuration (Force Routing Through Ubuntu)

## 1. Set default route towards Ubuntu
```bash
sudo ip route del default
sudo ip route add default via 192.168.56.102 dev eth1
```

### Verify
```bash
ip route
```

✅ Expected:
```
default via 192.168.56.102 dev eth1
192.168.56.0/24 dev eth1
192.168.1.0/24 dev eth0
```

Kali will now send **all IPv4 internet traffic** to Ubuntu.

---

# ✅ Verification Tests

Below are the tests performed from Kali to validate routing.

---

## ✅ 1. Ping IPv4 Internet
```bash
ping -c 4 8.8.8.8
```

✅ Expected: Replies received  
✅ NAT + forwarding working

Example output:
```
64 bytes from 8.8.8.8: icmp_seq=1 ttl=111 time=55 ms
```

---

## ✅ 2. Curl IPv4 Website
```bash
curl -4 https://example.com
```

✅ Expected: HTML output  
✅ IPv4 TCP connections working through router

---

## ✅ 3. Traceroute (hop-by-hop)
```bash
traceroute -n 8.8.8.8
```

✅ Expected Output:
```
1  192.168.56.102   (Ubuntu Router)
2  192.168.31.1     (Home Router)
3  192.0.0.1        (ISP NAT)
...
```

This proves the *exact* path of your packets.

---

# ✅ Router Packet Capture Verification (Ubuntu)

To confirm NAT + routing:

## ✅ Capture LAN → Ubuntu (enp0s8)
```bash
sudo tcpdump -i enp0s8 -n icmp
```
✅ Shows Kali → Ubuntu traffic.

## ✅ Capture WAN side (enp0s3)
```bash
sudo tcpdump -i enp0s3 -n icmp
```
✅ Shows Ubuntu → Internet with **translated IP** (MASQUERADE).

---

# ✅ IPv6 Behavior (Important Note)

- Kali gets IPv6 directly via VirtualBox / home router
- Ubuntu **does not route IPv6**
- This is expected and chosen for FireNetX
- Documentation covers IPv4-only router behavior

This simplifies:
- NAT  
- tcpdump  
- traceroute  
- security analysis  
- firewall rule inspection  

---

# ✅ Final Validation Checklist

✅ Ubuntu has **IPv4 internet**  
✅ Ubuntu LAN interface has **192.168.56.102**  
✅ IPv4 forwarding = **ON**  
✅ NAT MASQUERADE enabled  
✅ FORWARD rules enabled  
✅ SSH rules preserved  
✅ Kali’s default route points to Ubuntu  
✅ Kali traceroute shows Ubuntu → Home Router  
✅ IPv6 bypasses by design  

✅ **Your Ubuntu VM is now a fully functional IPv4 router.**

---

# ✅ Suggested Folder in Repo

```
FireNetX/
└── docs/
    └── router-verification.md
```

---

# ✅ Screenshots to Add (Optional)

Add screenshots in a folder:
```
docs/images/router/
```

Recommended:
- `ip_route_kali.png`
- `traceroute_kali.png`
- `tcpdump_enp0s8.png`
- `tcpdump_enp0s3.png`
- `ubuntu_ip_addr.png`

---

# ✅ Conclusion

Your FireNetX lab now uses a **realistic IPv4 routing setup** with:

- Full NAT
- Controlled routing paths
- Packet inspection
- Hybrid LAN/WAN separation
- Professional-level reproducibility

This document fully verifies your setup and can be used in reports, GitHub portfolio, and future cyber labs.

