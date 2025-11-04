# Fail2Ban Configuration

## Objective
Prevent brute-force login attempts by automatically banning IPs that exceed a set number of failed SSH logins.

## Installation and Setup
```bash
sudo apt install fail2ban -y
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local
```

## Configured jail.local (excerpt)
```ini
[sshd]
enabled  = true
port     = ssh
banaction = ufw
maxretry = 3
findtime = 5m
bantime  = 10m
```

## Service Enable & Verification
```bash
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
```

## Output
```text
Status for the jail: sshd
|- Filter
|  |- Currently failed: 0
|  `- Total failed: 6
`- Actions
   |- Currently banned: 1
   `- Total banned: 2
```

---


**✅ Confirmed working: failed SSH attempts trigger bans as expected.**
