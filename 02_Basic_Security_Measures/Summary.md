# Basic_Security_Measures

## Objective
This section focuses on applying essential security measures across all virtual machines in the FireNetX lab environment.  
The goal is to establish a secure baseline that prevents unauthorized access, enforces proper authentication, and ensures safe network communication.

## Summary of Completed Work
- Set up and verified a multi-VM topology (Kali, Ubuntu, Windows 10, Metasploitable)
- Configured Ubuntu as a router/firewall using IP forwarding and NAT (MASQUERADE)
- Created non-root administrative accounts and secured SSH with key-based authentication
- Disabled root login and password authentication
- Restricted SSH to a single allowed user
- Configured and enabled UFW with strict inbound and limited allowed ports
- Installed and configured Fail2Ban to automatically ban brute-force attempts
- Enabled HTTPS with a self-signed SSL certificate and verified redirection from HTTP to HTTPS
- My website (PadhoLikho.com) already deployed on Ubunut Server
- Performed connectivity and service verification using curl, ss, and ufw status

---

### Verification Summary
All configurations were tested successfully:
- **SSH login**: key-only access verified  
- **Firewall**: correct rules applied and active  
- **Fail2Ban**: detected and banned invalid SSH attempts  
- **Webserver**: HTTPS functional and redirect confirmed  

