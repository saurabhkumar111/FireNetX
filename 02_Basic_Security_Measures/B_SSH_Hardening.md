# 2. SSH Hardening

## Objective
Secure SSH access to the Ubuntu server using key-based authentication and proper configuration restrictions.

## Steps Performed
1. **Generated Key Pair (on Kali)**
   ```bash
   ssh-keygen -t ed25519 -C "FireNetX"

2. **Deployed Public Key to Ubuntu**
    ```bash
    ssh-copy-id portal_admin@192.168.56.102

3. **Set Permissions**
      ```bash
      chmod 700 ~/.ssh
      chmod 600 ~/.ssh/authorized_keys

4. **Updated /etc/ssh/sshd_config**
     ```bash
     PubkeyAuthentication yes
     PasswordAuthentication no
     KbdInteractiveAuthentication no
     PermitRootLogin no
     AllowUsers portal_admin

5. **Restarted SSH and Verified**
      ```bash
      sudo systemctl restart ssh
      ssh -v portal_admin@192.168.56.102


---
<img width="1918" height="437" alt="sshd" src="https://github.com/user-attachments/assets/e6a601f5-4e97-4b2f-b271-860785ed2ef9" />

---
**Verification**

Password login disabled ✅
Key authentication only ✅
Root login disabled ✅
User restriction applied ✅
