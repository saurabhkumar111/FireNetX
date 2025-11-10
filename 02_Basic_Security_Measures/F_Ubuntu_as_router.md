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
<img width="1905" height="352" alt="image" src="https://github.com/user-attachments/assets/31bfe236-23cd-4680-8ba1-8b1dfa263b32" />


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
<img width="1706" height="441" alt="image" src="https://github.com/user-attachments/assets/1e85cddd-9793-40d4-93ea-2208be3d2256" />


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

# ✅ Screenshots

**ip route**
<img width="1475" height="357" alt="image" src="https://github.com/user-attachments/assets/78ac46e9-8732-4173-a818-ef346db89d51" />
The ip route output shows Kali has two network interfaces and two possible default routes:

192.168.1.0/24 dev eth0 — Kali’s eth0 is on the 192.168.1.0 network with gateway 192.168.1.1.

192.168.56.0/24 dev eth1 — Kali’s eth1 is on the Host-Only network to Ubuntu.

There are two default routes listed. The kernel chooses which default to use based on route metrics and the momentary routing table state. In our tests we explicitly set the default route to via 192.168.56.102 dev eth1, so all IPv4 internet traffic from Kali is directed to the Ubuntu router (192.168.56.102) on eth1.

Why this proves routing via Ubuntu:

When the default route points to 192.168.56.102, packets destined for the Internet are forwarded to that IP rather than the home gateway on eth0. This is the first required condition for making the Ubuntu VM act as Kali’s IPv4 gateway.

**traceroute -n 8.8.8.8**
<img width="1217" height="585" alt="image" src="https://github.com/user-attachments/assets/001de5d6-f401-48fd-b9e0-3c3954880908" />

Hop 1 – 192.168.56.102 (Ubuntu Router)
Confirms Kali is sending traffic to Ubuntu as the default gateway.

Hop 2 – 192.168.31.1 (Home Router)
Shows Ubuntu is forwarding traffic to your home network’s router.

Hops 3–6 – 192.0.0.x
These are internal ISP routers (carrier NAT / internal routing). Seeing them is normal.

Final hop – 8.8.8.8
Confirms packets successfully travel through Ubuntu → home router → ISP → internet.

Summary:
Traceroute proves Kali’s packets are routed through Ubuntu (first hop), then out to the internet normally.

# ✅ Conclusion

Your FireNetX lab now uses a **realistic IPv4 routing setup** with:

- Full NAT
- Controlled routing paths
- Packet inspection
- Hybrid LAN/WAN separation
- Professional-level reproducibility

This document fully verifies your setup and can be used in reports, GitHub portfolio, and future cyber labs.

