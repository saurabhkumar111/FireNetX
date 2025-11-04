
# HTTPS Implementation

## Objective
Enable secure HTTPS access using SSL/TLS certificates and configure redirection from HTTP to HTTPS.

## Steps Performed

### 1. Enable Apache SSL Module
```bash
sudo a2enmod ssl
```

### 2. Generate Self-Signed Certificate
```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
-keyout /etc/ssl/private/firenetx.key \
-out /etc/ssl/certs/firenetx.crt
```

### 3. Configure Virtual Host
```apache
<VirtualHost *:443>
    ServerAdmin admin@firenetx.local
    DocumentRoot /var/www/html
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/firenetx.crt
    SSLCertificateKeyFile /etc/ssl/private/firenetx.key
</VirtualHost>
```

### 4. Redirect HTTP → HTTPS
```apache
RewriteEngine On
RewriteCond %{HTTPS} !=on
RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R=301,L]
```

## Verification
```bash
curl -Iv https://192.168.56.102
```

**Sample Output:**
```text
HTTP/1.1 200 OK
```

---

**✅ Output confirms HTTP/1.1 200 OK over HTTPS**

<img width="847" height="753" alt="image" src="https://github.com/user-attachments/assets/61161ed7-2b9d-41c7-ada8-99cb1ba9bf19" />















