


## 🧱 **4. Firewall_UFW.md**

# Firewall (UFW) Configuration

## Objective
Control network access using UFW (Uncomplicated Firewall) to allow only essential traffic.

## Steps
1. **Install and Enable**
   ```bash
   sudo apt install ufw -y
   sudo ufw enable
   
2. **Set Default Policies**
   ```bash
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   
3. **Allow Specific Ports**
   ```bash
   sudo ufw allow from 192.168.56.101 to any port 22 proto tcp comment 'SSH from Kali only'
   sudo ufw allow 80/tcp comment 'HTTP'
   sudo ufw allow 443/tcp comment 'HTTPS'
4. **Verify Status**
   ```bash
   sudo ufw status numbered

---
**Verication**

Unnecessary ports closed ✅

SSH is accessible only from Kali ✅

HTTP/HTTPS open and working ✅
   
 
