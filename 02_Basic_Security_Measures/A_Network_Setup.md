# 1. Network Setup

## Overview
Set up a simple network environment, such as your home network or a virtual lab with a router and one or two connected devices.  
For this project, a controlled **multi-VM virtual lab** was built in VirtualBox to simulate a secure enterprise environment.

## Topology Summary
| VM Name | Role | IP Address | Notes |
|----------|------|-------------|-------|
| Kali Linux | Attacker / Administrator | 192.168.56.101 | Used for SSH, testing, and analysis |
| Ubuntu Server | Router / Firewall / Web Server | 192.168.56.102 | Gateway + Apache + UFW + Fail2Ban |
| Windows 10 | Client System | 192.168.56.103 | Simulated user workstation |
| Metasploitable | Vulnerable Target | 192.168.56.104 | Used for later exploitation stages |

## Verification
- Internal communication successful (ping tests across VMs)
- Internet access functional through Ubuntu NAT
- Gateway confirmed via route tables and traceroute results
